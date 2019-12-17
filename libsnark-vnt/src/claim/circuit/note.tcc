/*****************************************************
 * note_gadget_with_packing for packing value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public:    
 
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    pb_variable_array<FieldT> value_c; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_c_packed;
    std::shared_ptr<digest_variable<FieldT>> r_c; // 256位的随机数r

    pb_variable_array<FieldT> L; // 合约计算的次数
    pb_variable<FieldT> L_packed;

    pb_variable_array<FieldT> N; // 最大支付次数
    pb_variable<FieldT> N_packed;

    pb_variable_array<FieldT> tmp; // 中间值
    pb_variable<FieldT> tmp_packed;

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s,
        pb_variable_array<FieldT> &value_c,
        std::shared_ptr<digest_variable<FieldT>> &r_c,
        pb_variable_array<FieldT> L,
        pb_variable_array<FieldT> N
    ) : gadget<FieldT>(pb), 
        value_s(value_s), 
        sn_s(sn_s),
        r_s(r_s),
        value_c(value_c),
        r_c(r_c),
        L(L),
        N(N)
    {        
        value_s_packed.allocate(pb, "value_s_packed");
        value_c_packed.allocate(pb, "value_c_packed");
        L_packed.allocate(pb, "L_packed");
        N_packed.allocate(pb, "N_packed");
        tmp_packed.allocate(pb, "tmp_packed");
        tmp.allocate(pb, 64);
    }

    void generate_r1cs_constraints() { // const Note& note
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_c[i],
                "boolean_value_c"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                L[i],
                "boolean_L"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                N[i],
                "boolean_N"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                tmp[i],
                "boolean_tmp"
            );
        }

        /* 
        value_s = value_c * L / N
        ==> N * value_s = value_c * L
        ==> N * value_s = tmp AND value_c * L = tmp
        */
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->N_packed, this->value_s_packed, this->tmp_packed),
                                 FMT(this->annotation_prefix, " equal"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->L_packed, this->value_c_packed, this->tmp_packed),
                                 FMT(this->annotation_prefix, " equal"));

        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
        r_c->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& notes, const NoteC& notec, uint64_t L_data, uint64_t N_data) { // 为变量生成约束        

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(notes.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);
        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));

        value_c.fill_with_bits(this->pb, uint64_to_bool_vector(notec.value));
        this->pb.lc_val(value_c_packed) = value_c.get_field_element_from_bits_by_order(this->pb);
        r_c->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notec.r));

        L.fill_with_bits(this->pb, uint64_to_bool_vector(L_data));
        this->pb.lc_val(L_packed) = L.get_field_element_from_bits_by_order(this->pb);

        N.fill_with_bits(this->pb, uint64_to_bool_vector(N_data));
        this->pb.lc_val(N_packed) = N.get_field_element_from_bits_by_order(this->pb);

        tmp.fill_with_bits(this->pb, uint64_to_bool_vector(L_data * notec.value));
        this->pb.lc_val(tmp_packed) = tmp.get_field_element_from_bits_by_order(this->pb);
    }
};