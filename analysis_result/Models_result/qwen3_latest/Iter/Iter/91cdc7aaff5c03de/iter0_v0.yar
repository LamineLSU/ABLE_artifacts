rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? }  // ExitProcess call with push 0
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }      // DeleteFileW call with push eax
        $pattern2 = { 33 DB FF 24 B5 ?? ?? ?? ?? }  // Jump table instruction with displacement

    condition:
        any of them
}