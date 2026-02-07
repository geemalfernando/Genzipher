const API = process.env.API_URL || "http://localhost:3000";

async function post(path, body, token) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function main() {
  const login = await post("/auth/login", {
    username: "doctor1",
    password: "password123",
    mfaCode: "123456",
  });
  if (login.status !== 200) throw new Error(`Login failed: ${JSON.stringify(login.json)}`);
  const token = login.json.token;

  const rxRes = await post(
    "/prescriptions",
    {
      patientUserId: "u_patient1",
      medicineId: "MED-AMOX-500",
      dosage: "500mg",
      durationDays: 7,
    },
    token
  );
  if (rxRes.status !== 201) throw new Error(`Rx create failed: ${JSON.stringify(rxRes.json)}`);
  const rx = rxRes.json;

  const verify1 = await post("/prescriptions/verify", { prescription: rx });
  console.log("Verify original:", verify1.json);

  const tampered = { ...rx, dosage: "999mg" };
  const verify2 = await post("/prescriptions/verify", { prescription: tampered });
  console.log("Verify tampered (dosage changed):", verify2.json);

  if (verify2.json?.ok) {
    throw new Error("Expected tampered prescription to fail verification.");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
