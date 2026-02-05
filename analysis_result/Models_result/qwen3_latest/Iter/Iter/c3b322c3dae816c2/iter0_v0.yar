rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push EBX + Call ExitProcess
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JE sandbox check
        $pattern2 = { 03 C3 03 C1 B9 ?? ?? ?? ?? }  // Add EAX + MOV ECX (address calc)

    condition:
        any of them
}