package com.boxever.cassandra.auth;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.apache.cassandra.auth.AllowAllAuthorizer;
import org.apache.cassandra.auth.Auth;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IAuthorizer;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.PermissionDetails;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import org.apache.cassandra.exceptions.UnauthorizedException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.apache.cassandra.utils.Pair;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class CassandraAuthorizer implements IAuthorizer
{
	private static final Logger logger = LoggerFactory.getLogger(CassandraAuthorizer.class);

	private static final String USERNAME = "username";
	private static final String RESOURCE = "resource";
	private static final String PERMISSIONS = "permissions";

	private static final String PERMISSIONS_CF = "permissions";
	private static final String PERMISSIONS_CF_SCHEMA = String.format("CREATE TABLE %s.%s ("
																	  + "username text,"
																	  + "resource text,"
																	  + "permissions set<text>,"
																	  + "PRIMARY KEY(username, resource)"
																	  + ") WITH gc_grace_seconds=%d",
																	  Auth.AUTH_KS,
																	  PERMISSIONS_CF,
																	  90 * 24 * 60 * 60); // 3 months.

	private SelectStatement authorizeStatement;

	private static LoadingCache<Pair<AuthenticatedUser, IResource>, Set<Permission>> permissionsCache;

	private static LoadingCache<Pair<AuthenticatedUser, IResource>, Set<Permission>> initPermissionsCache() {
		if (DatabaseDescriptor.getAuthorizer() instanceof AllowAllAuthorizer)
			return null;

		int validityPeriod = DatabaseDescriptor.getPermissionsValidity();
		if (validityPeriod <= 0)
			return null;

		int refreshPeriod = validityPeriod / 5;

		logger.info("Build Authenticator cache: expire after {} ms, refresh after {} ms", new Object[] { validityPeriod, refreshPeriod });

		return CacheBuilder.newBuilder().expireAfterWrite(validityPeriod, TimeUnit.MILLISECONDS)
									    .refreshAfterWrite(refreshPeriod, TimeUnit.MILLISECONDS)
									    .build(new CacheLoader<Pair<AuthenticatedUser, IResource>, Set<Permission>>()
									    {
										    public Set<Permission> load(Pair<AuthenticatedUser, IResource> userResource)
										    {
												logger.debug("Reloading Authenticator cache in background!");
									 		    return ((CassandraAuthorizer)DatabaseDescriptor.getAuthorizer())
												  .authorizeUserOnTheResource(userResource.left, userResource.right);
										    }
									    });
	}

	public Set<Permission> authorize(AuthenticatedUser user, IResource resource)
	{
		// AllowAllAuthorizer or manually disabled caching.
		if (permissionsCache == null)
		{
	  		return authorizeUserOnTheResource(user, resource);
		}

		try
		{
			return permissionsCache.get(Pair.create(user, resource));
		}
		catch (ExecutionException e)
		{
			throw new RuntimeException(e);
		}
	}

	public Set<Permission> authorizeUserOnTheResource(AuthenticatedUser user, IResource resource)
	{
		if (user.isSuper())
			return Permission.ALL;

		UntypedResultSet result;
		try
		{
			ResultMessage.Rows rows = authorizeStatement.execute(ConsistencyLevel.ONE,
																  new QueryState(new ClientState(true)),
																  Lists.newArrayList(ByteBufferUtil.bytes(user.getName()),
																	ByteBufferUtil.bytes(resource.getName())));
			result = new UntypedResultSet(rows.result);
		}
		catch (RequestValidationException e)
		{
			throw new AssertionError(e); // not supposed to happen
		}
		catch (RequestExecutionException e)
		{
			logger.warn("CassandraAuthorizer failed to authorize {} for {}", user, resource);
			return Permission.NONE;
		}

		if (result.isEmpty() || !result.one().has(PERMISSIONS))
			return Permission.NONE;

		Set<Permission> permissions = EnumSet.noneOf(Permission.class);
		for (String perm : result.one().getSet(PERMISSIONS, UTF8Type.instance))
			permissions.add(Permission.valueOf(perm));
		return permissions;
	}

	public void grant(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, String to)
	  throws RequestExecutionException
	{
		modify(permissions, resource, to, "+");
	}

	public void revoke(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, String from)
	  throws RequestExecutionException
	{
		modify(permissions, resource, from, "-");
	}

	// Adds or removes permissions from user's 'permissions' set (adds if op is "+", removes if op is "-")
	private void modify(Set<Permission> permissions, IResource resource, String user, String op) throws RequestExecutionException
	{
		process(String.format("UPDATE %s.%s SET permissions = permissions %s {%s} WHERE username = '%s' AND resource = '%s'",
							  Auth.AUTH_KS,
							  PERMISSIONS_CF,
							  op,
							  "'" + StringUtils.join(permissions, "','") + "'",
							  escape(user),
							  escape(resource.getName())));
	}

	// 'of' can be null - in that case everyone's permissions have been requested. Otherwise only single user's.
	// If the user requesting 'LIST PERMISSIONS' is not a superuser OR his username doesn't match 'of', we
	// throw UnauthorizedException. So only a superuser can view everybody's permissions. Regular users are only
	// allowed to see their own permissions.
	public Set<PermissionDetails> list(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, String of)
	  throws RequestValidationException, RequestExecutionException
	{
		if (!performer.isSuper() && !performer.getName().equals(of))
			throw new UnauthorizedException(String.format("You are not authorized to view %s's permissions",
			  of == null ? "everyone" : of));

		Set<PermissionDetails> details = new HashSet<PermissionDetails>();

		for (UntypedResultSet.Row row : process(buildListQuery(resource, of)))
		{
			if (row.has(PERMISSIONS))
			{
				for (String p : row.getSet(PERMISSIONS, UTF8Type.instance))
				{
					Permission permission = Permission.valueOf(p);
					if (permissions.contains(permission))
						details.add(new PermissionDetails(row.getString(USERNAME),
						  DataResource.fromName(row.getString(RESOURCE)),
						  permission));
				}
			}
		}

		return details;
	}

	private static String buildListQuery(IResource resource, String of)
	{
		List<String> vars = Lists.newArrayList(Auth.AUTH_KS, PERMISSIONS_CF);
		List<String> conditions = new ArrayList<String>();

		if (resource != null)
		{
			conditions.add("resource = '%s'");
			vars.add(escape(resource.getName()));
		}

		if (of != null)
		{
			conditions.add("username = '%s'");
			vars.add(escape(of));
		}

		String query = "SELECT username, resource, permissions FROM %s.%s";

		if (!conditions.isEmpty())
			query += " WHERE " + StringUtils.join(conditions, " AND ");

		if (resource != null && of == null)
			query += " ALLOW FILTERING";

		return String.format(query, vars.toArray());
	}

	// Called prior to deleting the user with DROP USER query. Internal hook, so no permission checks are needed here.
	public void revokeAll(String droppedUser)
	{
		try
		{
			process(String.format("DELETE FROM %s.%s WHERE username = '%s'", Auth.AUTH_KS, PERMISSIONS_CF, escape(droppedUser)));
		}
		catch (Throwable e)
		{
			logger.warn("CassandraAuthorizer failed to revoke all permissions of {}: {}", droppedUser, e);
		}
	}

	// Called after a resource is removed (DROP KEYSPACE, DROP TABLE, etc.).
	public void revokeAll(IResource droppedResource)
	{

		UntypedResultSet rows;
		try
		{
			// TODO: switch to secondary index on 'resource' once https://issues.apache.org/jira/browse/CASSANDRA-5125 is resolved.
			rows = process(String.format("SELECT username FROM %s.%s WHERE resource = '%s' ALLOW FILTERING",
			  Auth.AUTH_KS,
			  PERMISSIONS_CF,
			  escape(droppedResource.getName())));
		}
		catch (Throwable e)
		{
			logger.warn("CassandraAuthorizer failed to revoke all permissions on {}: {}", droppedResource, e);
			return;
		}

		for (UntypedResultSet.Row row : rows)
		{
			try
			{
				process(String.format("DELETE FROM %s.%s WHERE username = '%s' AND resource = '%s'",
				  Auth.AUTH_KS,
				  PERMISSIONS_CF,
				  escape(row.getString(USERNAME)),
				  escape(droppedResource.getName())));
			}
			catch (Throwable e)
			{
				logger.warn("CassandraAuthorizer failed to revoke all permissions on {}: {}", droppedResource, e);
			}
		}
	}

	public Set<DataResource> protectedResources()
	{
		return ImmutableSet.of(DataResource.columnFamily(Auth.AUTH_KS, PERMISSIONS_CF));
	}

	public void validateConfiguration() throws ConfigurationException
	{
	}

	public void setup()
	{
		if (Schema.instance.getCFMetaData(Auth.AUTH_KS, PERMISSIONS_CF) == null)
		{
			try
			{
				process(PERMISSIONS_CF_SCHEMA);
			}
			catch (RequestExecutionException e)
			{
				throw new AssertionError(e);
			}
		}

		try
		{
			String query = String.format("SELECT permissions FROM %s.%s WHERE username = ? AND resource = ?", Auth.AUTH_KS, PERMISSIONS_CF);
			authorizeStatement = (SelectStatement) QueryProcessor.parseStatement(query).prepare().statement;
		}
		catch (RequestValidationException e)
		{
			throw new AssertionError(e); // not supposed to happen
		}

		permissionsCache = initPermissionsCache();
	}

	// We only worry about one character ('). Make sure it's properly escaped.
	private static String escape(String name)
	{
		return StringUtils.replace(name, "'", "''");
	}

	private static UntypedResultSet process(String query) throws RequestExecutionException
	{
		return QueryProcessor.process(query, ConsistencyLevel.ONE);
	}
}
