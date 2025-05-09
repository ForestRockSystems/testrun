<img width="200" alt="Testrun logo" src="https://user-images.githubusercontent.com/7399056/221927867-4190a4e8-a571-4e40-9c2b-65780ad9264c.png" alt="Testrun">

# Get started

This page covers the following topics:

- [Get started](#get-started)
- [Prerequisites](#prerequisites)
  - [Hardware](#hardware)
  - [Software](#software)
  - [Device](#device)
- [Installation](#installation)
- [Testing](#testing)
  - [Start Testrun](#start-testrun)
  - [Test your device](#test-your-device)
- [Additional Configuration Options](/docs/additional_config.md)
- [Troubleshooting](#troubleshooting)
- [Review the report](#review-the-report)
- [Uninstall](#uninstall)

# Prerequisites

We recommend that you run Testrun on a stand-alone machine that has a fresh install of Ubuntu 22.04 or 24.04 LTS (laptop or desktop).

## Hardware

Before you start, ensure you have the following hardware:

-  PC running Ubuntu 22.04 or 24.04 LTS (laptop or desktop)
-  2x ethernet ports (USB ethernet adapters work too)
-  Internet connection

![Required hardware for Testrun](/docs/ui/getstarted--2dn8vrzsspe.png)

Note: If you're using Testrun in a virtual machine, follow the steps on the [Virtual machine page](/docs/virtual_machine.md).

## Software

Install Docker on your Ubuntu LTS PC using [the installation guide](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository). The following system dependencies install automatically when you install Testrun:

-  Python3-dev
-  Python3-venv
-  Openvswitch Common
-  Openvswitch Switch
-  Build Essential
-  Net Tools
-  Ethtool

## Device

You can test any device with an Ethernet connection and support for IPv4 DHCP. However, to achieve a compliant test outcome, you must configure your device correctly and implement the required security features. The [Application Security Requirements for IoT Devices](https://partner-security.withgoogle.com/docs/iot_requirements) outlines these standards. Additional details are available on the [Test modules page](/docs/test/modules.md).

# Installation

Follow these steps to install Testrun:

1. Download the latest version of the Testrun installer from the [Releases page](https://github.com/google/testrun/releases).
2. Open a terminal and navigate to the location of the Testrun installer (most likely your Downloads folder).
3. Install the package using `sudo apt install ./testrun*.deb`

Testrun installs under the `/usr/local/testrun` directory. Testing data is available in the `local/devices/{device}/reports` folders.

![Terminal during install](/docs/setup/install.gif)

# Testing

## Start Testrun

Follow these steps to start Testrun:
1. Attach the network interfaces.
    -  Connect one USB Ethernet adapter to the internet source (e.g., router or switch) using an Ethernet cable.
    -  Connect the other USB Ethernet adapter directly to the IoT device you want to test using an Ethernet cable.

    Notes:
    
    -  Disable both adapters in the host system (IPv4, IPv6, and general) by opening **Settings**, then **Network**.
    -  Keep the DUT powered off until prompted. Otherwise, Testrun will not be able to fully capture the device behavior during startup - resulting in inaccurate test results.

1. Start Testrun with the command `sudo testrun`
    -  To run Testrun in network-only mode (without running any tests), use the `--net-only` option.
    -  To run Testrun with just one interface (connected to the device), use the `--single-intf` option.
    
          **Note**: Tests that require an internet connection (e.g TLS client, DNS) will produce a non-compliant result.

## Test your device

Follow these steps to test your IoT device:

1. Open Testrun by navigating  to [http://localhost:8080](http://localhost:8080/) in your browser.
2. Select the **Settings** menu in the top-right corner. It will open the **General** tab by default. Then select your network interfaces. You can change the settings at any time.
     ![Settings menu button](/docs/ui/getstarted-settings-menu.png)
3. Select  the **Certificates** tab (Settings menu), then upload your local CA certificates for TLS server testing.
     ![Certificates menu button](/docs/ui/getstarted-certificates-menu.png)
4. Select the **Device Repository** icon on the left panel to add a new device for testing.  
     ![Device repository button](/docs/ui/getstarted-device-repository.png)

    Or

    Click the **Actions** button to add a new device for testing.
   ![Actions button](/docs/ui/getstarted-actions-device.png)
5. Select the **Add Device** button on the Device repository.
   ![Add device](/docs/ui/getstarted-add-device.png)
6. Enter the MAC address, manufacturer name, and model number.
7. Select Qualification or Pilot program.
8. Select the test modules you want to enable for this device.   
Note: For qualification purposes, you must select all.
9. Answer a few questions about your device.
10. Select **Save**.
11. Select the Testrun progress icon, then select the **Testing** button.![Testing button](/docs/ui/getstarted-testing.png)

    Or

    Click the **Actions** button, then select the **Start Testing** button.
    ![Actions button](/docs/ui/getstarted-actions-testing.png)

12. Select the device you want to test.
13. Enter the version number of the firmware running on the device.
14. Select **Start Testrun**.
  -  If you need to stop Testrun during testing, select **Stop** next to the test name.
15. Once the Waiting for Device notification appears, power on the device under test.
   ![Waiting for device](/docs/ui/getstarted-waiting-for-device.png)
16. While testing is in progress, you could complete a Risk Assessment. To do so, go to the **Risk assessment** tab.
   ![Risk assessment](/docs/ui/getstarted-risk-assessment.png)
17. A report appears under the Reports icon once the test sequence is complete.  
   ![Reports button](/docs/ui/getstarted-reports.png)

# Troubleshooting

If you encounter any issues, try the following:

-  Ensure that your computer meets all hardware and software prerequisites.
-  Verify that the network interfaces are connected correctly.
-  Check the configuration settings.
-  Refer to the [Testrun documentation](/docs).

If you still need assistance, ask a question on the [Issues page](https://github.com/google/testrun/issues). 

# Review the report

Once you complete a test attempt, you can review the test report provided by Testrun. For more information on Testrun requirements and outputs, refer to the [Testing documentation](/docs/test/README.md).

# Uninstall

To uninstall Testrun correctly, use the built-in dpkg uninstall command: `sudo apt-get remove testrun`
