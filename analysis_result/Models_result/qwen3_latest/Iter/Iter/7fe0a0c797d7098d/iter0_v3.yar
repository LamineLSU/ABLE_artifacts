rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Test EAX + JZ + MOV EAX
        $pattern1 = { FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? }  // Call ExitProcess + Push EBX
        $pattern2 = { 85 C0 74 12 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JNZ + PUSH/POP/Call

    condition:
        any of them
}