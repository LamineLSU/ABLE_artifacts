rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 74 54 41 00 85 C0 74 10 }  // Call IsWindowVisible + Test EAX + JE
        $pattern1 = { FF 15 3C 51 41 00 6A 00 FF 15 3C 51 41 00 }  // ExitProcess call + Push 0 + Call ExitProcess
        $pattern2 = { 83 7D 10 00 75 32 FF 15 28 54 41 00 }  // CMP EBP+10h + JNE + Call Shell_NotifyIconA

    condition:
        any of them
}