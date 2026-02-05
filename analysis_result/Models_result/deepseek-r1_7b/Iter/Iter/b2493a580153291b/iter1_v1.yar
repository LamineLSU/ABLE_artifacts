rule Bypass_Evasion_Bypass
{
    meta:
        description = "Evasion bypass by skipping specific calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }  // Bypass a call to F331CDh by changing its offset
        $pattern1 = { E8 17 D0 ?? ?? ?? }  // Bypass a call at address 0x00E817D0 with wildcarded offset
        $pattern2 = { C1 E8 EA 08 ?? ?? ?? }  // Bypass conditional jump condition in loop

    condition:
        any of them
}