use std::collections::HashMap;

use num_bigint::BigUint;

struct MeetInTheMiddle {
    p: BigUint,                 // modulus
    g: BigUint,                 // generator / log base
    map: HashMap<BigUint, u32>  // maps h*g^(-t) --> t
}

impl MeetInTheMiddle {
    fn new(p: BigUint, g: BigUint, h: BigUint) -> Self
    {
        let mut map: HashMap<BigUint, u32> = HashMap::new();

        // fill the map accumulating h*a^x1 with a=g^(-1) x1=0,...,2^20
        let a = g.modpow(&(&p-2u32), &p);
        let mut acc = h.clone();
        map.insert(acc.clone(), 0);
        for x1 in 1..(1 << 20) {
            acc = (&acc * &a) % &p;
            map.insert(acc.clone(), x1);
        }

        Self {p, g, map}
    }

    fn solve(&self) -> Option<(u32, u32)>
    {
        // for x0=0,...,2^20, find b^x0 in the table, with b=g^(2^20)
        let b = self.g.modpow(&BigUint::from((1 << 20) as u32), &self.p);
        let mut acc = BigUint::from(1 as u32);
        for x0 in 0..(1 << 20) {
            if let Some(&x1) = self.map.get(&acc) {
                return Some((x0, x1));
            }
            acc = (&acc * &b) % &self.p;
        }
        None
    }
}

fn main()
{
    let p: BigUint = "134078079299425970995740249982058461274793658205923933777235614437217640\
                      300735469768018742981669034276900318581864860508537538828119465699464336\
                      49006084171".parse().unwrap();

    let g: BigUint = "117178298803662070095161175963353670885580849999989522055999794590639294\
                      997365837466705721764714603129285948296754282794665665271152127484675898\
                      94601965568".parse().unwrap();

    let h: BigUint = "323947510405045044356526437872806578864909752095244952783479245297198197\
                      614329255807385693795855318053287892800149470609739410857758573245230767\
                      3444020333".parse().unwrap();

    let mim = MeetInTheMiddle::new(p, g, h);
    let res = mim.solve();

    match res {
        None => { println!("Unable to solve"); }
        Some((x0, x1)) => {
            let x = (u64::from(x0) << 20) + u64::from(x1);
            println!("Result: {}", x);
        }
    }
}
