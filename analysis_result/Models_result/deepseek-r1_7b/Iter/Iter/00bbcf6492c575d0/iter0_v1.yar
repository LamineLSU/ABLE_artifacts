rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns used in the VM"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B CE E8 25 05 00 00 FF 15 2C A1 FB 00 }  ; TEST followed by JZ and function call
        $pattern1 = { 85 C0 F9 7E 00 00 01 6A 5B 53 03 C3 0F 84 33 FD FF FF E8 CE B6 00 00 FF 15 2C A1 68 01 }  ; Stack manipulation and jump
        $pattern2 = { 85 C0 F9 7E 00 00 01 6A 5B 53 03 C3 0F 84 33 FD FF FF E8 CE B6 00 00 FF 15 2C A1 C1 01 }  ; Similar to $pattern1 but with different offset
    condition:
        any of them
}