pragma solidity ^0.8.0;

contract access_control {

    // Structs to store information about managers, devices and rules
    struct Manager {
        string name;
        address managerAddress;
    }

    struct Device {
    string name;
    uint deviceId;
    address deviceAddress;
    address[] managers;
}

    struct Rule {
        address managerAddress;
        address constrainedDeviceAddress;
        address newDeviceAddress;
        uint resource;
        string accessRights;
        uint expirationBlock;
    }

    // Mapping to store information about registered managers, devices and rules
    mapping(address => Manager) public managers;
    mapping(uint => Device) public devices;
    mapping(address => mapping(address => Rule)) public rules;

    uint deviceNumber = 0;

    // Events to notify clients of important contract events
    event ManagerRegistered(string name, address managerAddress);
    event DeviceRegistered(string name, uint deviceId, address deviceAddress);
    event ManagerAddedToDevice(uint deviceId, address managerAddress);
    event ManagerRemovedFromDevice(uint deviceId, address managerAddress);
    event RuleAdded(address managerAddress, address constrainedDeviceAddress, address newDeviceAddress, uint resource, string accessRights, uint expirationBlock);
    event ManagerDeRegistered(address managerAddress);
    event DeviceDeRegistered(uint deviceId);
    event PermissionRevoked(uint deviceId, address managerAddress);

    // Function to register a manager
      function registerManager(address managerAddress, string memory name) public {
        require(managers[managerAddress].managerAddress == address(0), "Manager already registered.");
        managers[managerAddress] = Manager(name, managerAddress);
        emit ManagerRegistered(name, managerAddress);
    }

    //Function to register a device
    function registerDevice(string memory name, uint deviceId, address deviceAddress) public {
        //Check that device is not already registered
        require(devices[deviceId].deviceAddress == address(0), "Device already registered.");
        address[] memory emptyArray = new address[](0);
        devices[deviceId] = Device(name, deviceId, deviceAddress, emptyArray);
        deviceNumber++;
        emit DeviceRegistered(name, deviceId , deviceAddress);
    }

    //Function to add a manager to a device

    function addManagerToDevice(uint deviceId, address managerAddress) public {
        //Check that manager is registered
        require(managers[managerAddress].managerAddress != address(0), "Manager not registered.");
        //Check that device is registered
        require(devices[deviceId].deviceAddress != address(0), "Device not registered.");
        //Check that the manager is not already added to the device but first check for the null devices[deviceId] case
        for(uint i=0;i<devices[deviceId].managers.length;i++){
        require(devices[deviceId].managers[i] != managerAddress, "Manager already added to device.");
        }
        
        //Add the manager to the device
        devices[deviceId].managers.push(managerAddress);

        //Add the device to the manager
        emit ManagerAddedToDevice(deviceId, managerAddress);
    }
    

    // Function to remove a manager from a device
    function removeManagerFromDevice(uint deviceId, address managerAddress) public {
        //Check that manager is added to the device
            bool managerFound = false;
            for(uint i=0;i<devices[deviceId].managers.length;i++){
                if(devices[deviceId].managers[i] == managerAddress){
                    managerFound = true;
                    break;
                }
            }
            require(managerFound, "Manager not added to device.");

        //Remove the manager from the device
        for (uint i = 0; i < devices[deviceId].managers.length; i++) {
            if (devices[deviceId].managers[i] == managerAddress) {
                devices[deviceId].managers[i] = devices[deviceId].managers[devices[deviceId].managers.length - 1];
                devices[deviceId].managers.pop();
                break;
            }
        }
        emit ManagerRemovedFromDevice(deviceId, managerAddress);
    }

    function addRule(address managerAddress, address constrainedDeviceAddress, address newDeviceAddress, uint resourceAccess, string memory accessRights, uint expirationBlocks) public returns (bool) {
    // Check that the caller of the function is the manager
    require(msg.sender == managerAddress, "Only the manager can add a rule");

    //Find the constrained device index in devices array
    bool constrainedDeviceFound = false;  
    uint constrainedDeviceIndex = 0;
    for (uint i = 0; i <= deviceNumber; i++) {
        if (devices[i].deviceAddress == constrainedDeviceAddress) {
            constrainedDeviceFound = true;
            constrainedDeviceIndex = i;
            break;
        }
    }

    // Check that the constrained device is registered
    require(constrainedDeviceFound, "Constrained device does not exist");

    // Check that the manager is registered
    require(managers[managerAddress].managerAddress != address(0), "Manager is not registered");

    // Check that the manager is added to the constrained device
    bool managerFound = false;
    for (uint i = 0; i < devices[constrainedDeviceIndex].managers.length; i++) {
        if (devices[constrainedDeviceIndex].managers[i] == managerAddress) {
            managerFound = true;
            break;
        }
    }
    require(managerFound, "Manager is not added to the constrained device");

    //Find the new device's index in devices array
    bool newDeviceFound = false;
    uint newDeviceIndex = 0;
    for (uint i = 0; i <= deviceNumber; i++) {
        if (devices[i].deviceAddress == newDeviceAddress) {
            newDeviceFound = true;
            newDeviceIndex = i;
            break;
        }
    }

    // Check that the new device is registered
    require(newDeviceFound, "New device does not exist");

    // Check that the constrained device is not the new device
    require(constrainedDeviceAddress != newDeviceAddress, "Constrained device and new device are the same");

    // Check that the constrained device is not already allowed to access the new device
    require(!isAllowedDevice(constrainedDeviceAddress, newDeviceAddress) || rules[constrainedDeviceAddress][newDeviceAddress].expirationBlock < block.number, "Constrained device is already allowed to access the new device");

    // Check that the expiration block is not in the past
    require(expirationBlocks > block.number, "Expiration block is in the past.");

    // Add the rule
    rules[constrainedDeviceAddress][newDeviceAddress] = Rule(managerAddress, constrainedDeviceAddress, newDeviceAddress, resourceAccess, accessRights, expirationBlocks);
    emit RuleAdded(managerAddress, constrainedDeviceAddress, newDeviceAddress, resourceAccess, accessRights, expirationBlocks);
    return true;

}

    function isAllowedDevice(address constrainedDeviceAddress, address newDeviceAddress) public view returns (bool) {
        return rules[constrainedDeviceAddress][newDeviceAddress].constrainedDeviceAddress != address(0);
    }

    
    function deregisterManager (address managerAddress) public {
        require(managers[managerAddress].managerAddress != address(0), "Manager not registered.");
        delete managers[managerAddress];
        emit ManagerDeRegistered(managerAddress);
    }
    

    function removeDevice (uint deviceId) public {
        require(devices[deviceId].deviceAddress != address(0), "Device not registered.");
        delete devices[deviceId];
        deviceNumber--;
        emit DeviceDeRegistered(deviceId);

    //remove device from the list of managed devices for each manager
    for (uint i = 0; i < devices[deviceId].managers.length; i++) {
        removeManagerFromDevice(deviceId, devices[deviceId].managers[i]);
    }

    }

    //function to revoke permission
    function revokePermission(address manager, address constrainedDevice, address newDevice) public {
        //Check that manager exists
        require(managers[manager].managerAddress != address(0), "Manager does not exist.");

        //Find the constrained device index in devices array
        uint constrainedDeviceIndex = 0;
        bool constrainedDeviceFound = false;
        for (uint i = 0; i <= deviceNumber; i++) {
            if (devices[i].deviceAddress == constrainedDevice) {
                constrainedDeviceFound = true;
                constrainedDeviceIndex = i;
                break;
            }
        }

        require(constrainedDeviceFound, "Constrained device does not exist");

        //Find the new device's index in devices array
        uint newDeviceIndex = 0;
        bool newDeviceFound = false;
        for (uint i = 0; i <= deviceNumber; i++) {
            if (devices[i].deviceAddress == newDevice) {
                newDeviceFound = true;
                newDeviceIndex = i;
                break;
            }
        }
        require(newDeviceFound, "New device does not exist");

        // Check if there is an existing rule for the given pair of devices
        require(isAllowedDevice(constrainedDevice, newDevice), "No rule exists for the given pair of devices");

        // Ensure the sender is the manager who created the rule
        require(rules[constrainedDevice][newDevice].managerAddress == msg.sender, "Only the manager who created the rule can revoke it");

        // Remove the rule
        delete rules[constrainedDevice][newDevice];

        //Logic that deviceId equals to the index of the device in the devices array
        uint deviceId = constrainedDeviceIndex;

        // Emit an event to notify clients of the rule revocation
        emit PermissionRevoked(deviceId, manager);
    
    }


        function getManager(address managerAddress) public view returns (string memory, address) {
        //Check that manager exists
        require(managers[managerAddress].managerAddress != address(0), "Manager does not exist.");
        return (managers[managerAddress].name, managers[managerAddress].managerAddress);
    }

        function queryPermission(address constrainedDevice, address newDevice) public view returns (bool, string memory, uint, uint) {
        //Find the constrained device index in devices array
        uint constrainedDeviceIndex = 0;
        bool constrainedDeviceFound = false;
        for (uint i = 0; i <= deviceNumber; i++) {
            if (devices[i].deviceAddress == constrainedDevice) {
                constrainedDeviceFound = true;
                constrainedDeviceIndex = i;
                break;
            }
        }

        require(constrainedDeviceFound, "Constrained device does not exist");

        //Find the new device's index in devices array
        uint newDeviceIndex = 0;
        bool newDeviceFound = false;
        for (uint i = 0; i <= deviceNumber; i++) {
            if (devices[i].deviceAddress == newDevice) {
                newDeviceFound = true;
                newDeviceIndex = i;
                break;
            }
        }
        require(newDeviceFound, "New device does not exist");

        // Check if there is an existing rule for the given pair of devices
        require(isAllowedDevice(constrainedDevice, newDevice), "No rule exists for the given pair of devices"); {
        }

        // Check if the rule has expired
        require(block.number < rules[constrainedDevice][newDevice].expirationBlock, "No unexpired rule exists for the given pair of devices"); {
        }


        return (true, rules[constrainedDevice][newDevice].accessRights, rules[constrainedDevice][newDevice].resource, rules[constrainedDevice][newDevice].expirationBlock - block.number);

        }

        //Function to check whether a device is registered
        function isDeviceRegistered(address deviceAddress) public view returns (bool, string memory, uint, address, address[] memory) {
        //Find the device index in devices array
        uint deviceIndex = 0;
        bool deviceFound = false;
        for (uint i = 0; i <= deviceNumber; i++) {
            if (devices[i].deviceAddress == deviceAddress) {
                deviceFound = true;
                deviceIndex = i;
                break;
            }
        }

        require(deviceFound, "Device does not exist");
        
        return (true, devices[deviceIndex].name, devices[deviceIndex].deviceId, devices[deviceIndex].deviceAddress, devices[deviceIndex].managers);
        }

}

    