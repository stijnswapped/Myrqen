import {DefaultCrudRepository, juggler} from '@loopback/repository';
import {inject} from '@loopback/core';

export interface StockItem {
  id: string;
  companyId: string;
  sku: string;
  description: string;
  onHand: number;
  unitCostCents: number;
  supplierRef: string;
}

export interface StockItemRelations {}

/** Plain CRUD over the `stock_item` table on the PostgreSQL datasource. */
export class StockRepository extends DefaultCrudRepository<
  StockItem,
  typeof StockItem.prototype.id,
  StockItemRelations
> {
  constructor(@inject('datasources.warehouse') dataSource: juggler.DataSource) {
    super(Object.assign({}, {name: 'StockItem'}) as never, dataSource);
  }

  /** Escape hatch for the two reports whose shape the query builder cannot express. */
  async raw<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    return this.dataSource.execute(sql, params) as Promise<T[]>;
  }
}

declare namespace StockItem {
  const prototype: {id: string};
}
