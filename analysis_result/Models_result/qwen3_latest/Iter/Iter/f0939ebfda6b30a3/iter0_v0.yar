rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 03 FF 15 ?? ?? ?? ?? }  // Push 3 + Call ExitProcess
        $pattern1 = { 57 FF 15 ?? ?? ?? ?? }     // Push edi + Call WaitForMultipleObjects
        $pattern2 = { 85 FF 74 ?? }              // Test edi + Je conditional jump

    condition:
        any of them
}