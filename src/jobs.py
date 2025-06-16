from .auth import get_credential
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

def list_backup_jobs(subscription_id, resource_group, vault_name):
    credential = get_credential()
    client = RecoveryServicesBackupClient(credential, subscription_id)
    print(f"Listing backup jobs for vault: {vault_name}")
    jobs = client.backup_jobs.list(resource_group, vault_name)
    for job in jobs:
        print(f"Job: {job.name} | Status: {job.status} | Operation: {job.operation} | Start: {job.start_time}")