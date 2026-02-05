rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push EBX + Call ExitProcess (address wildcards)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JE (conditional jump offset wildcards)
        $pattern2 = { BA 04 01 00 00 50 E8 ?? ?? ?? ?? }  // MOV EDX + PUSH + CALL (displacement wildcards)

    condition:
        any of them
}