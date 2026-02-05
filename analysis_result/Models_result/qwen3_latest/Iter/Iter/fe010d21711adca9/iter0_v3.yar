rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A }  // Test EAX + JE + Push/Pop sequence
        $pattern1 = { BA 04 01 00 00 50 E8 ?? ?? ?? ?? }  // MOV EDX + PUSH + CALL with offset
        $pattern2 = { 50 FF 15 88 A0 0C 01 }  // PUSH + CALL CloseHandle@KERNEL32 with address

    condition:
        any of them
}