rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? }  // ExitProcess call with surrounding push
        $pattern1 = { 85 C0 E9 ?? ?? ?? ?? }  // Test EAX and conditional jump to ExitProcess
        $pattern2 = { 68 00 30 00 00 FF 15 ?? ?? ?? ?? }  // VirtualAlloc call with preceding push

    condition:
        all of them
}