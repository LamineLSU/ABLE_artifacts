rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Test EAX + JZ + MOV EAX
        $pattern1 = { FF 15 2C A1 2F 00 53 FF 15 88 A0 2F 00 }  // Call ExitProcess + Push EBX + Call CloseHandle
        $pattern2 = { 85 C0 74 07 50 FF 15 88 A0 2F 00 }  // Test EAX + JZ + Push EAX + Call CloseHandle

    condition:
        any of them
}