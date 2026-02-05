rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 52 50 51 FF D2 5E 5D C3 94 99 AD 77 B8 6F C1 84 81 6A 00 55 8B EC DD EC EA 74 AA FF 96 FF FF FF EC }
        $pattern2 = { 83 C4 14 52 8B 16 50 51 FF D2 5E 5D }

    condition:
        any of them
}