from .auth import get_credential
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.recoveryservicesbackup.models import BackupRequestResource, IaasVMBackupRequest

def trigger_backup(subscription_id, resource_group, vault_name, container_name, item_name):
    credential = get_credential()
    client = RecoveryServicesBackupClient(credential, subscription_id)
    backup_request = BackupRequestResource(
        properties=IaasVMBackupRequest(recovery_point_expiry_time_in_utc="2025-12-31T23:59:59Z")
    )
    async_backup = client.backups.trigger(resource_group, vault_name, container_name, item_name, backup_request)
    print("Backup triggered. Operation ID:", async_backup.result().operation_id)