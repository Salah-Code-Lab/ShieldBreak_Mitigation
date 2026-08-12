# ShieldBreak_Mitigation

This is a Direct Response to ShieldBreak Vulnerability 

This is not my best work and i am not that proud of it since it only stops one thing 
and if that one thing was not Operation Critical then i'd need to Revamp this again which is hell 

I will be Iterating one this one for a While until i am sure 
and even when i am sure 

i do not know if there was any Sidesteps or anything else 
if there was and i discovered it 

Know this: 
i will attempt to Fix it if i could 
but the Exploit is already Flinicky and requires the Object Manager Subsystem 
i wanted to do that 

but the Structures and the Undocumented API's were not worth it 

the Only way if i truly wanted to Stop it dead in its tracks is 
Patch the SSDT, Patch Ntoskrnl.exe directly via physical pages to fail KeBugCheckEx so PatchGuard wont be able to call it (Requires HVCI off)
by that you failed the failure mechanism 
and you can take over

This took me time to Analyze especially because it juggles multiple Types of callbacks at once which made me blind bot not when i saw that Old ass Abuse
Cdlft,
Flt,
OB (Object Manager)


either way enough talking 
if there was any issues Notify me via my Session ID: 
056bf8ea1a057b4f351d8b651944252cd4d88416ce6c11761f0c406f228a302301


and don't forget to raise an issue
i am always watching 


