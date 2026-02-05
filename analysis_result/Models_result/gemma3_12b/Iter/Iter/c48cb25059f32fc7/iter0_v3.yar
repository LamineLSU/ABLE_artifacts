rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF } // Bypass call eax at 00419F27
        $pattern1 = { 8D 85 7C FD FF FF BA 02 00 00 00 E8 3A CD FF FF } // Bypass call 00403B98h at 00419F53
        $pattern2 = { E8 31 FD FF FF 5E 8B F0 B9 0B 00 00 00 F3 A5 } // Bypass call 004034AE at 004034AE

    condition:
        any of them
}