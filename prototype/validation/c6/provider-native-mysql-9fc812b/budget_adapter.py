"""Pure classification of captured fresh3 budget output and its receipt.
No file, process, device or database access. STOP can never authorize a lane.
"""
MINIMUM_BYTES = 4_294_967_296
OWNER_KEY = 'io.pushgo.c6.disk3.synthetic.owner'

def classify_budget(stdout, receipt, container_id, owner_uuid):
 def require(ok, reason):
  if not ok:
   raise ValueError('invalid budget evidence: '+reason)
 def integer(value):
  return isinstance(value, int) and not isinstance(value, bool) and value >= 0
 require(isinstance(stdout, dict) and isinstance(receipt, dict), 'objects required')
 require(isinstance(stdout.get('receipt'), str) and bool(stdout['receipt']), 'receipt reference missing')
 require(receipt.get('container_id') == container_id, 'container ownership mismatch')
 require(receipt.get('owner_uuid') == owner_uuid, 'owner UUID mismatch')
 require(receipt.get('volume_owner_label_key') == OWNER_KEY, 'volume owner key mismatch')
 require(receipt.get('volume_owner_label_value') == owner_uuid, 'volume owner value mismatch')
 require(receipt.get('storage_medium') == 'disk-backed-named-volume', 'storage medium mismatch')
 require(receipt.get('volume_driver') == 'local', 'volume driver mismatch')
 require(receipt.get('volume_name') == 'pushgo-c6-disk3-data-'+owner_uuid, 'volume name mismatch')
 require(receipt.get('minimum_available_bytes') == MINIMUM_BYTES, 'fixed4GiB minimum missing or changed')
 require(receipt.get('os_snapshot_persisted_before_sql') is True, 'OS-first receipt missing')
 for field in ['available_bytes', 'host_available_bytes', 'guard_effective_available_bytes']:
  require(integer(receipt.get(field)), field+' missing or invalid')
 effective = min(receipt['available_bytes'], receipt['host_available_bytes'])
 require(receipt['guard_effective_available_bytes'] == effective, 'effective minimum inconsistent')
 require(type(receipt.get('guard_pass')) is bool, 'receipt guard result missing')
 require(type(stdout.get('guard_pass')) is bool, 'stdout guard result missing')
 require(receipt['guard_pass'] == (effective >= MINIMUM_BYTES), 'guard threshold inconsistent')
 require(stdout['guard_pass'] == receipt['guard_pass'], 'stdout/receipt guard mismatch')
 status = receipt.get('status')
 inventory = receipt.get('sql_inventory')
 require(isinstance(inventory, dict), 'SQL inventory missing')
 if status == 'STOP_INSUFFICIENT4GIB':
  require(not receipt['guard_pass'], 'insufficient-space STOP cannot have passing guard')
  require(stdout.get('status', status) == status, 'STOP status mismatch')
  require(stdout.get('effective_available_bytes') == effective, 'STOP effective bytes mismatch')
  require(inventory.get('status') == 'NOT_ATTEMPTED', 'insufficient-space STOP must precede SQL')
  return {'decision':'STOP','status':status,'receipt':stdout['receipt'],'effective_available_bytes':effective,'minimum_available_bytes':MINIMUM_BYTES,'reason':'original fixed4GiB guard rejected; no native/Gateway authorization'}
 require(status in ('BUDGET_READY', 'STOP_SQL_INVENTORY_FAILURE'), 'unrecognized or missing receipt status')
 require(stdout.get('status') == status, 'stdout status missing or mismatched')
 require(stdout.get('storage_medium') == receipt['storage_medium'], 'stdout medium mismatch')
 require(stdout.get('volume_name') == receipt['volume_name'], 'stdout volume mismatch')
 for field in ['available_bytes', 'host_available_bytes']:
  require(stdout.get(field) == receipt[field], 'stdout '+field+' mismatch')
 require(receipt['guard_pass'], 'READY/SQL-inventory result requires passing OS budget')
 if status == 'STOP_SQL_INVENTORY_FAILURE':
  require(inventory.get('status') == 'FAILED_STOP_NO_RETRY' and isinstance(inventory.get('exit_code'), int) and inventory['exit_code'] != 0, 'SQL failure receipt inconsistent')
  return {'decision':'STOP','status':status,'receipt':stdout['receipt'],'reason':'original SQL inventory failed; no retry or native/Gateway authorization'}
 require(inventory.get('status') == 'COMPLETE' and inventory.get('exit_code') == 0, 'READY SQL inventory incomplete')
 return {'decision':'READY','status':status,'receipt':stdout['receipt'],'effective_available_bytes':effective,'minimum_available_bytes':MINIMUM_BYTES}
