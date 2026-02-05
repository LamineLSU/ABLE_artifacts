rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting sandbox calls"
        cape_options = "bp0=E8??25??00??00??,action0=skip,bp1=74FA??,action1=skip,bp2=C3???,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 25 05 } // Call at 0x40840100
        $pattern1 = { 74 FA ?? } // Call at 0x40872600 with wildcarded offset
        $pattern2 = { C3 ?? ??? } // Call at 0x40E7C3h with wildcarded operands

    condition:
        any of them
}