// MongoDB initialization script for NextGCore
// Creates indexes and initial data for the nextgcore database

// Switch to nextgcore database
db = db.getSiblingDB('nextgcore');

// Create indexes for subscribers collection
db.subscribers.createIndex({ "imsi": 1 }, { unique: true });
db.subscribers.createIndex({ "msisdn": 1 });

// Create indexes for NF instances
db.nfInstances.createIndex({ "nfInstanceId": 1 }, { unique: true });
db.nfInstances.createIndex({ "nfType": 1 });
db.nfInstances.createIndex({ "nfStatus": 1 });

// Create indexes for sessions
db.sessions.createIndex({ "supi": 1 });
db.sessions.createIndex({ "pduSessionId": 1 });
db.sessions.createIndex({ "dnn": 1 });

// Create indexes for policy data
db.policyData.createIndex({ "supi": 1 });

// Create admin user for webui
db.accounts.createIndex({ "username": 1 }, { unique: true });
db.accounts.insertOne({
    username: "admin",
    // Default password: 1423 (hashed)
    password: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    roles: ["admin"],
    created: new Date()
});

// Insert a test subscriber (IMSI: 001010123456789)
db.subscribers.insertOne({
    imsi: "001010123456789",
    msisdn: ["821012345678"],
    security: {
        k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
        opc: "E8ED289DEBA952E4283B54E88E6183CA",
        amf: "8000"
    },
    ambr: {
        uplink: { value: 1, unit: 3 },      // 1 Gbps
        downlink: { value: 1, unit: 3 }      // 1 Gbps
    },
    slice: [
        {
            sst: 1,                          // eMBB
            default_indicator: true,
            session: [
                {
                    name: "internet",
                    type: 3,                 // IPv4v6
                    qos: {
                        index: 9,
                        arp: {
                            priority_level: 8,
                            pre_emption_capability: 1,
                            pre_emption_vulnerability: 1
                        }
                    },
                    ambr: {
                        uplink: { value: 1, unit: 3 },
                        downlink: { value: 1, unit: 3 }
                    }
                }
            ]
        }
    ],
    access_restriction_data: 32,
    subscriber_status: 0,
    network_access_mode: 0,
    subscribed_rau_tau_timer: 12,
    created: new Date()
});

print("NextGCore MongoDB initialization completed.");
print("Default admin user created (username: admin, password: 1423)");
print("Test subscriber created (IMSI: 001010123456789)");
