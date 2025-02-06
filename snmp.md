# Offensive SNMP Pentesting Cheat Sheet

**Overview**  
SNMP (Simple Network Management Protocol) is used for managing and monitoring network devices. In many environments, default or weak SNMP community strings (e.g., "public" for read-only, "private" for read-write) remain unchanged. This can expose sensitive device information such as system details, network interfaces, routing tables, and even command-line credentials. SNMP v1 and v2c transmit community strings in plaintext, making them an attractive target during penetration testing. SNMP v3 adds encryption and authentication but is not always deployed.

---

## Key Offensive Considerations
- **Enumeration:** Leverage SNMP to gather detailed device information.
- **Brute Force:** Use tools to discover valid community strings.
- **Exploitation:** If write access is available, use SNMP to modify device parameters.
- **Recon:** Extract network topology, software versions, and service details for further exploitation.

---

## Common Commands & Tools

- **snmpwalk**  
  Recursively queries a target device to enumerate SNMP data.  
  Example: `snmpwalk -v 2c -c public <target-ip> 1.3.6.1.2.1.1`  
  *Use this to retrieve system information such as hostname, uptime, and more.*

- **snmpget**  
  Retrieves a specific OID from the target device.  
  Example: `snmpget -v 2c -c public <target-ip> 1.3.6.1.2.1.1.5.0`  
  *Typically used to fetch the system name (hostname).*

- **onesixtyone**  
  Brute forces SNMP community strings using a dictionary file.  
  Example: `onesixtyone -c dict.txt <target-ip>`  
  *Useful for discovering default or weak community strings.*

- **snmpset**  
  Modifies SNMP values when write access is granted (using the read-write community string).  
  Example: `snmpset -v 2c -c private <target-ip> 1.3.6.1.2.1.1.5.0 s "NewHostname"`  
  *Use with caution; unauthorized changes can disrupt network operations.*

---

## Offensive Tips
- **Target Default Strings:** Always test for "public" and "private" before trying more complex brute force methods.
- **Enumerate Widely:** Explore various OIDs beyond system info, such as:
  - `1.3.6.1.2.1.2` for network interfaces.
  - `1.3.6.1.2.1.25` for system inventory.
- **Combine Data:** SNMP findings can reveal credentials, network architecture, and running services, which are valuable for lateral movement.
- **Document Findings:** Keep detailed records of discovered community strings and device details for further exploitation and reporting.

---
