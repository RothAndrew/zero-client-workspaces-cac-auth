# zero-client-workspaces-cac-auth
Figuring out how to do Amazon Workspaces using a Zero Client with DOD CAC smartcard auth

## Instructions
1. Make a `iac/terraform.tfvars` file with your values
1. Apply the terraform code
    ```shell
    cd iac
    terraform init
    terraform apply
    ```

## Notes

- The Windows EC2 instance for Active Directory does not have a public IP address or port 3389 open for security reasons. To RDP to it you have to use `aws ssm start-session` to set up port forwarding, then you can RDP to `localhost:<theport>`.
    ```shell
    aws ssm start-session --target <TheInstanceID> --document-name AWS-StartPortForwardingSession --parameters "localPortNumber=54321,portNumber=3389" --region <TheRegion>
    ```

## Known Issues

- The DSRM password is visible in the user data script. It should be set some other way.
