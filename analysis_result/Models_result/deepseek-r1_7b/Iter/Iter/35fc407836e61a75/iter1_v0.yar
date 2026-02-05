rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns from specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  ; Basic near call with context
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? }  ; Varied displacement pattern 
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }    ; Multiple stack manipulation