rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF 8B 4E 04 E8 ?? ?? ?? ?? } // XOR EDI,EDI + MOV EAX,EDI + CALL (offset varies)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC } // TEST EAX + JE + MOV EAX, [ESP+0Ch] (specific stack offset)
        $pattern2 = { FF 15 ?? ?? ?? ?? 8B 4E 04 E8 ?? ?? ?? ?? } // CALL [addr] + MOV EAX,EDI + CALL (offset varies)

    condition:
        any of them
}