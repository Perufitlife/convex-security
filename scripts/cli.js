#!/usr/bin/env node
import { run } from "./audit.js";
run().catch((e) => { console.error(e.message); process.exit(1); });
