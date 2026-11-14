// D445A subscribers (nextgsim#480): imsi-99970000000000N, N = 1..5, each with the
// External Identifier ueNNN@fl.nextg (`extid`, emitted by udrd as the GPSI
// extid-ueNNN@fl.nextg, nextgcore#1490). Runs after mongo-init.js (the
// docker-entrypoint-initdb.d order): copies its ...001 to ...002-005.
db = db.getSiblingDB('nextgcore');
const base = db.subscribers.findOne({ imsi: "999700000000001" }, { _id: 0 });
if (!base) { throw new Error("mongo-init.js seeded no imsi 999700000000001"); }
for (let n = 1; n <= 5; n++) {
  const s = Object.assign({}, base);
  s.imsi = "99970000000000" + n;
  s.msisdn = ["82100000000" + n];
  s.extid = "ue00" + n + "@fl.nextg";
  db.subscribers.updateOne({ imsi: s.imsi }, { $set: s }, { upsert: true });
  print("d445a seeded imsi-" + s.imsi + " extid " + s.extid);
}
