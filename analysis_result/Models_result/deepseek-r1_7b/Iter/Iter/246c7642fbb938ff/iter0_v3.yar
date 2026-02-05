rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using multiple bypass points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 # MO V EA X, [E BP +8 H] FF 75 08 # PU SH DW OR D PT R [E BP +8 H] (O FF SE T 0) E8 C8 FF FF FF # CA LL 00 40 E7 C3 H ?? # WI LD CA RD FO R AD DR ES S AF TE R CA LL ?? ?? # WI LD CA RD FO R OF FS ET AF TE R CA LL ?? # WI LD CA RD FO R NE XT IN ST RU CT IO N AF TE R CA LL }
        $pattern1 = { FF 75 08 # PU SH DW OR D PT R [E BP +8 H] (O FF SE T 0) E8 C8 FF FF FF # CA LL 00 40 E7 C3 H ?? # WI LD CA RD FO R AD DR ES S BE FO RE CA LL ?? ?? # WI LD CA RD FO R OF FS ET BE FO RE CA LL ?? # WI LD CA RD FO R NE XT IN ST RU CT IO N AF TE R CA LL FF 15 AC B0 41 00 # CA LL DW OR D PT R [0 04 1B 0A CH ] }
        $pattern2 = { 8B EC # MO V EB P, ES P E8 C8 FF FF FF # CA LL 00 40 E7 C3 H ?? # WI LD CA RD FO R AD DR ES S BE FO RE CA LL ?? ?? # WI LD CA RD FO R OF FS ET AF TE R CA LL ?? # WI LD CA RD FO R NE XT IN ST RU CT IO N }
    condition:
        any of them
}