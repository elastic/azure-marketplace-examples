
# Deploy a cluster configured with Logstash Azure Monitor module

Run the PowerShell script in this directory. Once the script has finished and deployed all necessary resources,
a one-time set of operations need to be performed to setup the Azure Monitor module:

1. SSH into Logstash through Kibana VM

    ```sh
    ssh <adminname>@<kibana ip>
    ```

    Then SSH into the Logstash VM from the Kibana VM

    ```sh
    ssh logstash-0
    ```

2. Stop the running Logstash service with systemctl

    ```sh
    sudo systemctl stop logstash.service
    ```

3. Remove `path.config` setting from `/etc/logstash/logstash.yml`. The config file can't be used in conjunction with Azure modules

    ```sh
    sudo nano /etc/logstash/logstash.yml
    ```

4. Need to run one time setup for Logstash module to export Dashboards to Kibana.

    Get the keystore password from `/etc/sysconfig/logstash` and export to environment variables

    ```sh
    logstashPass=$(sudo grep -Po "(?<=^LOGSTASH_KEYSTORE_PASS=).*" /etc/sysconfig/logstash | sed 's/"//g')

    export LOGSTASH_KEYSTORE_PASS="$logstashPass"
    ```

5. Run the Logstash setup with logstash user, passing environment variables

    ```sh
    sudo -Eu logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --setup
    ```

6. Once `[Azure Monitor]` Dashboards appear under the Dashboard tab in Kibana, stop Logstash with `CTRL+C`, as we're going to restart
it as a service managed by systemd next.

7. Start Logstash service with systemctl

    ```sh
    sudo systemctl start logstash.service
    ```