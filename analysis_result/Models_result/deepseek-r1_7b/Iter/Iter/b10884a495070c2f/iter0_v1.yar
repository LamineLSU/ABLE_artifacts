rule Bypass_Sample
{
    meta:
        description = "Evasion bypass sequences detected in two traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 DB E8 EC FF ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 53 F7 0F C0 FF C4 FF ?? ?? ?? ?? 90 FF FF FF FF ?? ?? ?? 8B 2E FF FF FF FF 6A 53 F7 0F C0 FF }
        $pattern2 = { E8 7C 74 1B EC FF 1D FF FF ?? ?? 8B FC FB FF FF FF FF ?? ?? ?? 6A 00 FF 1F FF FF FF FF ?? }
    condition:
        any of them
}