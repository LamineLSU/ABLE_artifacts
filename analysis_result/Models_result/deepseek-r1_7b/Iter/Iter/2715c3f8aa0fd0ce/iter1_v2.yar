rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC # PU SH EB P E8 F7 25 00 # CA LL DF 02 H WI TH OF FS ET ?? AN D 00 83 F8 01 # CO MP AR E AL TO 01 74 20 # JU MP IF NO T EQ UA L TO 01 (J E) FF 75 08 # PU SH SO ME DA TA TO ST AC K }
        $pattern1 = { E8 F7 ?? ?? # CA LL DF 02 H WI TH UN KN OW N OF FS ET (? ?) 0F 84 # DI SP LA CE ME NT OF ?? BY TE S FR OM PR EV IO US PU SH ?? :? # WI LD CA RD FO R AN Y OF FS ET AF TE R TE ST FF 75 08 # PU SH SO ME DA TA TO ST AC K 8B C9 # PU SH -1 TO TH E ST AC K (W IL DC AR D) }
        $pattern2 = { 6A ?? # IN ST RU CT IO N WI TH AD DR ES S AT +? ? AN D ?? 5A ?? # IN ST RU CT IO N WI TH AD DR ES S AT +? ? 8B CE # MO VE VA LU E FR OM PC +? ? TO R0 E8 F7 05 00 # CA LL DF 02 H WI TH OF FS ET 05 (W IL DC AR D) }

    condition:
        any_ofthem
}