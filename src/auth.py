from azure.identity import DefaultAzureCredential

def get_credential():
    return DefaultAzureCredential()