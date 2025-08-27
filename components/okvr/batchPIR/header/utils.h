#ifndef UTILS_H
#define UTILS_H

#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cstdint>
#include <vector>
#include "database_constants.h"
#include "seal/seal.h"

typedef std::vector<seal::Ciphertext> PIRQuery;
typedef seal::Ciphertext PIRResponse;
typedef std::vector<seal::Ciphertext> PIRResponseList;
typedef std::vector<std::vector<unsigned char>> RawDB;
typedef std::vector<std::vector<unsigned char>> RawResponses;
typedef std::vector<uint64_t> Row;
typedef std::vector<Row> PirDB;
using namespace std;
using namespace seal;

namespace utils
{

    // Returns the next power of 2 for a given number
    inline size_t next_power_of_two(size_t n)
    {
        return pow(2, ceil(log2(n)));
    }

    // Generates a random number between 0 and max_value
    inline uint32_t generate_random_number(uint32_t max_value)
    {
        return rand() % (max_value + 1);
    }

    // Prints an error message and exits the program with an error code
    inline void error_exit(const std::string &error_message, int error_code = 1)
    {
        std::cerr << "Error: " << error_message << std::endl;
        exit(error_code);
    }

    // Prints a message to the console
    inline void print_message(const std::string &message)
    {
        std::cout << message << std::endl;
    }

    inline std::vector<uint64_t> rotate_vector_row(std::vector<uint64_t> &vec, int rotation_Amount)
    {
        if (vec.empty())
        {
            return {};
        }

        const size_t row_size = vec.size() / 2;
        rotation_Amount = rotation_Amount % row_size;

        std::vector<uint64_t> temp(vec.size(), 0ULL);
        for (size_t i = 0; i < row_size; ++i)
        {
            temp[(i + rotation_Amount) % row_size] = vec[i];
            temp[(i + rotation_Amount) % row_size + row_size] = vec[i + row_size];
        }
        return temp;
    }

    inline std::vector<uint64_t> rotate_vector_col(std::vector<uint64_t> &vec)
    {
        if (vec.empty())
        {
            return {};
        }

        const size_t row_size = vec.size() / 2;

        uint64_t tmp_slot = 0;
        for (size_t i = 0; i < row_size; ++i)
        {
            tmp_slot = vec[i];
            vec[i] = vec[row_size + i];
            vec[row_size + i] = tmp_slot;
        }

        return vec;
    }

    // 计算哈希值并对总桶数取模
    inline std::size_t hash_mod(size_t id, size_t nonce, size_t data, size_t total_buckets)
    {
        std::hash<std::string> hasher1; // 创建一个哈希函数对象
        // 将id、nonce和data转换为字符串并连接，然后计算哈希值
        return hasher1(std::to_string(id) + std::to_string(nonce) + std::to_string(data)) % total_buckets; // 返回哈希值对总桶数的余数
    }

    /*
    函数的主要功能是根据给定的数据、候选数量和总桶数，生成一组候选桶的索引
    */
    inline std::vector<size_t> get_candidate_buckets(size_t data, size_t num_candidates, size_t total_buckets)
    {
        // 存储候选桶的容器
        std::vector<size_t> candidate_buckets;

        // 遍历需要的候选数量
        for (int i = 0; i < num_candidates; i++)
        {
            size_t nonce = 0; // 初始的nonce值
            // 使用hash_mod函数计算桶索引
            auto bucket = hash_mod(i, nonce, data, total_buckets);

            // 如果该桶已存在于候选桶中，继续计算下一个桶
            while (std::find(candidate_buckets.begin(), candidate_buckets.end(), bucket) != candidate_buckets.end())
            {
                nonce += 1; // 增加nonce值
                // 重新计算桶索引
                bucket = hash_mod(i, nonce, data, total_buckets);
            }
            // 将计算出的唯一桶添加到候选桶列表中
            candidate_buckets.push_back(bucket);
        }

        // 返回候选桶的索引列表
        return candidate_buckets;
    }

    inline void multiply_acum(uint64_t op1, uint64_t op2, __uint128_t &product_acum)
    {
        product_acum = product_acum + static_cast<__uint128_t>(op1) * static_cast<__uint128_t>(op2);
    }

    inline seal::EncryptionParameters create_encryption_parameters(string selection = "")
    {
        seal::EncryptionParameters seal_params(seal::scheme_type::bfv);

        // Generally this parameter selectioon will work
        const int PolyDegree = 8192;
        int PlaintextModBitss = 22;
        vector<int> CoeffMods = {55, 55, 48, 60};
        seal_params.set_poly_modulus_degree(PolyDegree);

        if (selection == "256,10485,256" || selection == "256,10485,32")
        {
            // use these parameters when internal PIR is 2d and no merging is needed at the end
            PlaintextModBitss = 26;
            CoeffMods = {55, 55, 60};
        }
        else if (selection == "32,1048576,32" || selection == "64,1048576,32" || selection == "256,104857,32")
        {
            // use these parameters when internal PIR is 3d but no merging is needed at the end
            PlaintextModBitss = 28;
            CoeffMods = {42, 58, 58, 60};
        }

        seal_params.set_coeff_modulus(CoeffModulus::Create(PolyDegree, CoeffMods));
        seal_params.set_plain_modulus(PlainModulus::Batching(PolyDegree, PlaintextModBitss));

        std::cout << "+---------------------------------------------------+" << std::endl;
        std::cout << "|             SEAL ENCRYPTION PARAMETERS            |" << std::endl;
        std::cout << "+---------------------------------------------------+" << std::endl;
        std::cout << "|  seal_params_.poly_modulus_degree  = " << seal_params.poly_modulus_degree() << std::endl;

        auto coeff_modulus_size = seal_params.coeff_modulus().size();
        std::cout << "|  seal_params_.coeff_modulus().bit_count   = [";

        for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
        {
            std::cout << seal_params.coeff_modulus()[i].bit_count() << " + ";
        }

        std::cout << seal_params.coeff_modulus().back().bit_count();
        std::cout << "] bits" << std::endl;
        std::cout << "|  seal_params_.coeff_modulus().size = " << seal_params.coeff_modulus().size() << std::endl;
        std::cout << "|  seal_params_.plain_modulus().bit_count = " << seal_params.plain_modulus().bit_count() << std::endl;
        std::cout << "+---------------------------------------------------+" << std::endl;

        SEALContext context = SEALContext(seal_params);
        if (!context.parameters_set())
        {
            std::cout << "SEAL parameters not valid." << std::endl;
        }
        if (!context.first_context_data()->qualifiers().using_batching)
        {
            std::cout << "SEAL parameters do not support batching." << std::endl;
        }
        if (!context.using_keyswitching())
        {
            std::cout << "SEAL parameters do not support key switching." << std::endl;
        }

        return seal_params;
    }

    inline void multiply_poly_acum(const uint64_t *ct_ptr, const uint64_t *pt_ptr, size_t size, uint128_t *result)
    {
        for (int cc = 0; cc < size; cc += 32)
        {
            multiply_acum(ct_ptr[cc], pt_ptr[cc], result[cc]);
            multiply_acum(ct_ptr[cc + 1], pt_ptr[cc + 1], result[cc + 1]);
            multiply_acum(ct_ptr[cc + 2], pt_ptr[cc + 2], result[cc + 2]);
            multiply_acum(ct_ptr[cc + 3], pt_ptr[cc + 3], result[cc + 3]);
            multiply_acum(ct_ptr[cc + 4], pt_ptr[cc + 4], result[cc + 4]);
            multiply_acum(ct_ptr[cc + 5], pt_ptr[cc + 5], result[cc + 5]);
            multiply_acum(ct_ptr[cc + 6], pt_ptr[cc + 6], result[cc + 6]);
            multiply_acum(ct_ptr[cc + 7], pt_ptr[cc + 7], result[cc + 7]);
            multiply_acum(ct_ptr[cc + 8], pt_ptr[cc + 8], result[cc + 8]);
            multiply_acum(ct_ptr[cc + 9], pt_ptr[cc + 9], result[cc + 9]);
            multiply_acum(ct_ptr[cc + 10], pt_ptr[cc + 10], result[cc + 10]);
            multiply_acum(ct_ptr[cc + 11], pt_ptr[cc + 11], result[cc + 11]);
            multiply_acum(ct_ptr[cc + 12], pt_ptr[cc + 12], result[cc + 12]);
            multiply_acum(ct_ptr[cc + 13], pt_ptr[cc + 13], result[cc + 13]);
            multiply_acum(ct_ptr[cc + 14], pt_ptr[cc + 14], result[cc + 14]);
            multiply_acum(ct_ptr[cc + 15], pt_ptr[cc + 15], result[cc + 15]);
            multiply_acum(ct_ptr[cc + 16], pt_ptr[cc + 16], result[cc + 16]);
            multiply_acum(ct_ptr[cc + 17], pt_ptr[cc + 17], result[cc + 17]);
            multiply_acum(ct_ptr[cc + 18], pt_ptr[cc + 18], result[cc + 18]);
            multiply_acum(ct_ptr[cc + 19], pt_ptr[cc + 19], result[cc + 19]);
            multiply_acum(ct_ptr[cc + 20], pt_ptr[cc + 20], result[cc + 20]);
            multiply_acum(ct_ptr[cc + 21], pt_ptr[cc + 21], result[cc + 21]);
            multiply_acum(ct_ptr[cc + 22], pt_ptr[cc + 22], result[cc + 22]);
            multiply_acum(ct_ptr[cc + 23], pt_ptr[cc + 23], result[cc + 23]);
            multiply_acum(ct_ptr[cc + 24], pt_ptr[cc + 24], result[cc + 24]);
            multiply_acum(ct_ptr[cc + 25], pt_ptr[cc + 25], result[cc + 25]);
            multiply_acum(ct_ptr[cc + 26], pt_ptr[cc + 26], result[cc + 26]);
            multiply_acum(ct_ptr[cc + 27], pt_ptr[cc + 27], result[cc + 27]);
            multiply_acum(ct_ptr[cc + 28], pt_ptr[cc + 28], result[cc + 28]);
            multiply_acum(ct_ptr[cc + 29], pt_ptr[cc + 29], result[cc + 29]);
            multiply_acum(ct_ptr[cc + 30], pt_ptr[cc + 30], result[cc + 30]);
            multiply_acum(ct_ptr[cc + 31], pt_ptr[cc + 31], result[cc + 31]);
        }
    }

} // namespace utils

#endif // UTILS_H
