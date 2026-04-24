rule EvasionTechniques
{
    meta:
        description = "Detects potential evasion techniques using specific instruction sequences"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $b = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $c = { 7E BE ?? ?? ?? ?? }

    condition:
        all of them
}