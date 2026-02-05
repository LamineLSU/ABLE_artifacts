rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }  // CALL + PUSH EBP + MOV EBP + PUSH DWORD PTR [EBP+08h] - 12 bytes
        $pattern1 = { 00 40 E7 F6 E8 C8 FF FF FF } // CALL instruction itself - 10 bytes
        $pattern2 = { 00 40 E7 F0 55 8B EC } // PUSH EBP + MOV EBP - 8 bytes

    condition:
        any of them
}