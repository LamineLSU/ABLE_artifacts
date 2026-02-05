rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using stack manipulation and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 8A 45 8B 53 ?? ?? ?? ?? 8B 86 ?? AE CA EA AC AA BA AE CB AD CA EE AC }
        $pattern1 = { FF C0 2F 9D 45 45 73 45 5A 8B CE E8 ?? AE CA EA CD AB AA EA EC FC AD FC }
        $pattern2 = { 6A 10 ?? 5A 8B ?? ?? AE CA EA EE AC AA BA CB CA CA AE AC }

    condition:
        (any_of($pattern0, $pattern1, $pattern2))
}