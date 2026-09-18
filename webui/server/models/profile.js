const mongoose = require('mongoose');
const Schema = mongoose.Schema;
require('mongoose-long')(mongoose);

const Profile = new Schema({

  schema_version: {
    $type: Number,
    default: 1  // Current Schema Version
  },

  title: { $type: String, required: true },

  msisdn: [ String ],
  imeisv: [ String ],

  security: {
    k: String,
    op: String,
    opc: String,
    amf: String,
  },

  ambr: {
    downlink: { value: Number, unit: Number },
    uplink: { value: Number, unit: Number }
  },

  slice: [{
    sst: { $type: Number, required: true },
    sd: String,
    default_indicator: Boolean,
    session: [{
      name: { $type: String, required: true }, // DNN or APN
      type: Number,
      qos: {
        index: Number, // 5QI or QCI
        arp: {
          priority_level: Number,
          pre_emption_capability: Number,
          pre_emption_vulnerability: Number,
        }
      },
      ambr: {
        downlink: { value: Number, unit: Number },
        uplink: { value: Number, unit: Number }
      },
      ue: {
        ipv4: String,
        ipv6: String
      },
      smf: {
        ipv4: String,
        ipv6: String
      },
      pcc_rule: [{
        flow: [{
          direction: Number,
          description: String
        }],
        qos: {
          index: Number,
          arp: {
            priority_level: Number,
            pre_emption_capability: Number,
            pre_emption_vulnerability: Number,
          },
          mbr: {
            downlink: { value: Number, unit: Number },
            uplink: { value: Number, unit: Number }
          },
          gbr: {
            downlink: { value: Number, unit: Number },
            uplink: { value: Number, unit: Number }
          },
        },
      }],

      lbo_roaming_allowed: Boolean,
      // nextgcore #264: DnnInfo.defaultDnnIndicator (TS 29.503). Which DNN a UE
      // gets inside this slice when it requests none (TS 23.501 5.6.1). Distinct
      // from the slice-level `default_indicator` above, which picks the slice.
      default_dnn_indicator: Boolean

    }]
  }],

  subscriber_status: {
    $type: Number,
    default: 0  // Service Granted
  },
  operator_determined_barring: {
    $type: Number,
    default: 0 // No barring
  }

}, { typeKey: '$type' });

module.exports = mongoose.model('Profile', Profile);
