
#[test]
pub fn test_reenc_1_out_of_L_toy(){
    let pp = generate_pp_toy();
    let key_pair = generate_keys_toy(&pp);
    let msg = BigInt::from(72);
    // let ctx = &ElGamal::encrypt(&msg, &key_pair.pk).unwrap();
    let ctx = &encrypt_toy(&msg, &key_pair.pk).unwrap();
    let L = 3;
    /*
     let mut C_list: Vec<ElGamalCiphertext> = (0..L)
         .map(|_| ElGamal::encrypt(&BigInt::sample_below(&pp.q),&key_pair.pk ).unwrap())
         .collect();
     */
    let mut C_list: Vec<ElGamalCiphertext> = (0..L)
        .map(|_| encrypt_toy(&BigInt::sample_below(&BigInt::from(30)),&key_pair.pk ).unwrap())
        .collect();
    let t = 2;
    let enc_key = BigInt::from(7);
    let cipher = ElGamalCipherTextAndPK{ ctx: ctx.clone(), pk: &key_pair.pk };
    C_list[t] = reencrypt(&cipher,&enc_key);
    println!("div = {:?}",  &(&C_list[t].c1 * BigInt::mod_inv(&ctx.c1, &pp.p)).mod_floor(&pp.p));
    println!("cipher = {:?}",  &ctx.c1);
    println!("re-cipher = {:?}",  &C_list[t].c1);

    let input = ReencProofInput{ C_list, c: ctx.clone() };
    //let proof = input.reenc_1_out_of_L_prover(&pp,&key_pair.pk, t, enc_key, L);
    let proof = input.reenc_1_out_of_L_prover_toy(&pp,&key_pair.pk, t, enc_key, L);
    //let verification = input.reenc_1_out_of_L_verifier(&pp,&key_pair.pk, proof, L);
    let verification = input.reenc_1_out_of_L_verifier_toy(&pp,&key_pair.pk, proof, L);
    assert!(verification);
}

pub fn reenc_1_out_of_L_prover_toy(&self, pp: &ElGamalPP, pk: &ElGamalPublicKey, t: usize, eta: BigInt, L: usize) -> ReencProofOutput {
    if self.C_list.len() != L {
        panic!("Size of the list doesn't match the specified list length L")
    }
    if *pp != pk.pp {
        panic!("mismatch pp");
    }
    if t >= L {
        panic! {"t must be smaller than the size of the list"}
    }
    let mut list_d_i = Vec::with_capacity(L);
    let mut list_r_i = Vec::with_capacity(L);
    let mut list_a_i = Vec::with_capacity(L);
    let mut list_b_i = Vec::with_capacity(L);

    for _ in 0..L {
        list_d_i.push(BigInt::sample_below(&BigInt::from(20)));
        list_r_i.push(BigInt::sample_below(&BigInt::from(20)));
    }
    let mut u_i: &BigInt;
    let mut v_i: &BigInt;
    for i in 0..L {
        u_i = &self.C_list[i].c1;
        v_i = &self.C_list[i].c2;
        list_a_i.push((&(div_and_pow(&self.c.c1,u_i,  &list_d_i[i], &pp.p) *
            BigInt::mod_pow(&pp.g, &list_r_i[i], &pp.p))).mod_floor( &pp.p));

        list_b_i.push(BigInt::mod_floor(&(div_and_pow(&self.c.c2,v_i,  &list_d_i[i], &pp.p) *
            BigInt::mod_pow(&pk.h, &list_r_i[i], &pp.p)), &pp.p));
    }

    println!("div and pow {:?}", div_and_pow(&self.C_list[2].c1, &self.c.c1, &BigInt::one(), &BigInt::from(1019)));
    println!("g^r {:?}", BigInt::mod_pow(&pp.g, &list_r_i[2], &pp.p));


    let mut E = {
        let mut e_vec = Vec::new();
        e_vec.push(&self.c.c1);
        e_vec.push(&self.c.c2);
        for e in self.C_list.iter() {
            e_vec.push(&e.c1);
        }
        for e in self.C_list.iter() {
            e_vec.push(&e.c2);
        }
        e_vec
    };

    E.extend(list_a_i.iter());
    E.extend(list_b_i.iter());
    //  println!("E:{:#?}", E);
    println!("ai:{:#?}", list_a_i);

    //  let c = BigInt::from(5);
    let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
        &E)
                              , &pp.q);

    let w = BigInt::mod_floor(&(&eta.clone() * &list_d_i[t] + &list_r_i[t]), &pp.q);
    let sum: BigInt = list_d_i.iter().fold(BigInt::zero(), |a, b| a + b);
    let tmp = sum.clone() - &list_d_i[t];
    let d_t_old =  list_d_i[t].clone();
    let r_t_old = list_r_i[t].clone();
    list_d_i[t] = BigInt::mod_floor(&(c.clone() - tmp.clone())
                                    , &pp.q);
    list_r_i[t] = BigInt::mod_floor(&(&w - &eta * &list_d_i[t]), &pp.q);
    let b_t = BigInt::mod_floor(&(div_and_pow(&self.C_list[t].c2, &self.c.c2, &list_d_i[t].clone(), &pp.p) *
        BigInt::mod_pow(&pk.h, &list_r_i[t], &pp.p)), &pp.p);

    let exp = (d_t_old.clone() * eta.clone() + r_t_old.clone()).mod_floor(&pp.q);

    println!("exp = {:?}\n, c = {:?},b_i = {:?}\n, eta = {:?}, d_t_old = {:?}\n, w = {:?}\n,\
         sum = {:?}\n, tmp = {:?}\n, d_t_new = {:?}\n,
         r_t_old = {:?}\n, r_t_new = {:?}",exp, c, b_t, eta.clone(), d_t_old,w.clone(),
             sum.clone(),tmp.clone(), list_d_i[t], r_t_old, list_r_i[t]);
    ReencProofOutput { D: list_d_i.try_into().unwrap(), R: list_r_i.try_into().unwrap() }
}




pub fn reenc_1_out_of_L_verifier_toy(&self, pp: &ElGamalPP, pk: &ElGamalPublicKey, proof: ReencProofOutput, L: usize) -> bool {
    let mut list_a_i = Vec::with_capacity(L);
    let mut list_b_i = Vec::with_capacity(L);

    let mut u_i: &BigInt;
    let mut v_i: &BigInt;
    for i in 0..L {
        u_i = &self.C_list[i].c1;
        v_i = &self.C_list[i].c2;
        list_a_i.push((&(div_and_pow(&self.c.c1,u_i,  &proof.D[i], &pp.p) *
            BigInt::mod_pow(&pp.g, &proof.R[i], &pp.p))).mod_floor( &pp.p));

        list_b_i.push(BigInt::mod_floor(&(div_and_pow(&self.c.c2,v_i,  &proof.D[i], &pp.p) *
            BigInt::mod_pow(&pk.h, &proof.R[i], &pp.p)), &pp.p));
    }
    let check = (div_and_pow(&self.c.c1,&self.C_list[2].c1,  &proof.D[2], &pp.p) *
        BigInt::mod_pow(&pp.g, &proof.R[2], &pp.p));

    let mut E = {
        let mut e_vec = Vec::new();
        e_vec.push(&self.c.c1);
        e_vec.push(&self.c.c2);
        for e in self.C_list.iter() {
            e_vec.push(&e.c1);
        }
        for e in self.C_list.iter() {
            e_vec.push(&e.c2);
        }
        e_vec
    };

    E.extend(list_a_i.iter());
    E.extend(list_b_i.iter());
    // println!("E:{:#?}", E);
    let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&pp.q);

    let sum: BigInt = proof.D.iter().fold(BigInt::zero(), |a, b| a + b);
    let D = sum.mod_floor(&pp.q);

    return c == D
}
