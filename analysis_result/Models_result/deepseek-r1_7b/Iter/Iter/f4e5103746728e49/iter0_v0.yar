rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting memory addresses and stack operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A EA AD 0F 84 ?? ?? ?? ?? 8B CE ?? ?? 53 }
        $pattern1 = { 6A 5B 5A EA AD ?? ?? ?? ?? 8B CE ?? ?? 0F 84 ?? ?? 8D 95 EA ?? ?? EB 53 }
        $pattern2 = { FF 15 AC B0 CA ?? ?? ?? ?? 0F 84 ?? ?? 74 12 BE ?? ?? 0F 84 ?? ?? }
    condition:
        any of them
}