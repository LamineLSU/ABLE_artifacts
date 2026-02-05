rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF FF 15 ?? ?? ?? ?? }  // ExitProcess call with preceding xor
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? 53 }  // CloseHandle call with surrounding pushes
        $pattern2 = { 85 C0 74 12 6A 5B }         // Initial condition check and push sequence

    condition:
        all of them
}