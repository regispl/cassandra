/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cassandra.service.pager;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.db.*;
import org.apache.cassandra.db.filter.DataLimits;
import org.apache.cassandra.db.rows.Row;
import org.apache.cassandra.dht.*;
import org.apache.cassandra.exceptions.RequestExecutionException;

/**
 * Pages a RangeSliceCommand whose predicate is a slice query.
 *
 * Note: this only work for CQL3 queries for now (because thrift queries expect
 * a different limit on the rows than on the columns, which complicates it).
 */
public class RangeSliceQueryPager extends AbstractQueryPager
{
    private static final Logger logger = LoggerFactory.getLogger(RangeSliceQueryPager.class);

    private volatile DecoratedKey lastReturnedKey;
    private volatile Clustering lastReturnedClustering;

    public RangeSliceQueryPager(PartitionRangeReadCommand command, PagingState state)
    {
        super(command);
        assert !command.isNamesQuery();

        if (state != null)
        {
            lastReturnedKey = command.metadata().decorateKey(state.partitionKey);
            lastReturnedClustering = state.cellName.hasRemaining()
                                   ? LegacyLayout.decodeClustering(command.metadata(), state.cellName)
                                   : null;
            restoreState(lastReturnedKey, state.remaining, state.remainingInPartition);
        }
    }

    public PagingState state()
    {
        return lastReturnedKey == null
             ? null
             : new PagingState(lastReturnedKey.getKey(), LegacyLayout.encodeClustering(command.metadata(), lastReturnedClustering), maxRemaining(), remainingInPartition());
    }

    protected ReadCommand nextPageReadCommand(int pageSize)
    throws RequestExecutionException
    {
        DataLimits limits;
        DataRange fullRange = ((PartitionRangeReadCommand)command).dataRange();
        DataRange pageRange;
        if (lastReturnedKey == null)
        {
            pageRange = fullRange;
            limits = command.limits().forPaging(pageSize);
        }
        else
        {
            // We want to include the last returned key only if we haven't achieved our per-partition limit, otherwise, don't bother.
            boolean includeLastKey = remainingInPartition() > 0;
            AbstractBounds<PartitionPosition> bounds = makeKeyBounds(lastReturnedKey, includeLastKey);
            if (includeLastKey)
            {
                pageRange = fullRange.forPaging(bounds, command.metadata().comparator, lastReturnedClustering, false);
                limits = command.limits().forPaging(pageSize, lastReturnedKey.getKey(), remainingInPartition());
            }
            else
            {
                pageRange = fullRange.forSubRange(bounds);
                limits = command.limits().forPaging(pageSize);
            }
        }

        // it won't hurt for the next page command to query the index manager
        // again to check for an applicable index, so don't supply one here
        return new PartitionRangeReadCommand(command.metadata(), command.nowInSec(), command.columnFilter(), command.rowFilter(), limits, pageRange, Optional.empty());
    }

    protected void recordLast(DecoratedKey key, Row last)
    {
        if (last != null)
        {
            lastReturnedKey = key;
            lastReturnedClustering = last.clustering();
        }
    }

    protected boolean isPreviouslyReturnedPartition(DecoratedKey key)
    {
        // Note that lastReturnedKey can be null, but key cannot.
        return key.equals(lastReturnedKey);
    }

    private AbstractBounds<PartitionPosition> makeKeyBounds(PartitionPosition lastReturnedKey, boolean includeLastKey)
    {
        AbstractBounds<PartitionPosition> bounds = ((PartitionRangeReadCommand)command).dataRange().keyRange();
        if (bounds instanceof Range || bounds instanceof Bounds)
        {
            return includeLastKey
                 ? new Bounds<PartitionPosition>(lastReturnedKey, bounds.right)
                 : new Range<PartitionPosition>(lastReturnedKey, bounds.right);
        }
        else
        {
            return includeLastKey
                 ? new IncludingExcludingBounds<PartitionPosition>(lastReturnedKey, bounds.right)
                 : new ExcludingBounds<PartitionPosition>(lastReturnedKey, bounds.right);
        }
    }
}
