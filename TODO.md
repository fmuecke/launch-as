- [ ] Add a `quiet` or `verbose` switch that controls the broker messages for starting & stopping
- [ ] verbose mode could also print some more info like (t.b.d.)
- [ ] Discuss how to separate AppContainer capability configuration from execution, including loopback exemptions.
- [ ] Discuss MXC's lifecycle as a reference: provision the account, start/stop the session, then deprovision the account and clean up.


## To Check

- [ ] Discuss support for a workspace beneath a denied ancestor, e.g. `C:\dev\agentworkspace` when `C:\dev` is denied.
  - Distinguish launch-as's temporary denies from pre-existing explicit or inherited deny ACEs.
  - Define which ancestor access is required while keeping excluded sibling folders blocked; preserve unrelated ACLs.
  - Consider rejecting unsupported layouts before changing ACLs or starting the command, with an error identifying the conflicting ancestor.
  - Cover nested workspaces and existing denies in focused tests before claiming support.
