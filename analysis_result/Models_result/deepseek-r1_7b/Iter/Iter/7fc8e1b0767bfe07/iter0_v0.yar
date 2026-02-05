rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { E8 ?? ?? ?? ?? FF 97 FE 00 03 FF FE FF 03 ?? FF 0E 03 FF 03 FF 00 0D 02 00 00 5E FE FF FF C1 FC FF FF F4 E1 FC FF FF FF FF 00 00 71 73 6D 61 40 42 03 ?? 64 04 FE FF FF 0E 03 FF FF 05 E1 FC FF FF 8B DD FF 94 C1 FF FF 5A 00 5E FE FF FF 02 00 FF FF FE 00 5E FF FF 03 20 83 FF FF F5 FC FF FF 00 00 41 6D 7A 61 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}