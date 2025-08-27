#include <vector>
#include <ranges>

#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Matrix.h"

#include "batchPIR/header/batchpirparams.h"
#include "batchPIR/header/batchpirserver.h"
#include "batchPIR/header/batchpirclient.h"

#include "volePSI/PxUtil.h"
#include "volePSI/Paxos.h"

namespace deadline
{
    using namespace volePSI;
    using namespace oc;

    template <typename IdxType>
    class OkvrSender
    {
    public:
        Paxos<IdxType> mPaxos;
        BatchPIRServer mServer;

        // Paxos Data
        std::vector<block> mKeys;
        std::vector<block> mValues;
        std::vector<block> mEncoding;

        OkvrSender() {};

        void init(u64 numItems, block paxosHashSeed, u64 pirBatchSize = 128, u64 paxosWeight = 3, u64 paxosSsp = 40, PaxosParam::DenseType paxosDT = PaxosParam::GF128, u64 pirEntrySize = 16)
        {
            /*
            初始化 Paoxs
            */
            // 默认 w=3,denseType为GF128,统计参数为40
            PaxosParam pp(numItems, paxosWeight, paxosSsp, paxosDT);

            mKeys.resize(numItems);
            mValues.resize(numItems);
            mEncoding.resize(pp.size());

            // 检查n是否小于索引类型的最大值
            u64 maxN = std::numeric_limits<IdxType>::max() - 1;
            if (maxN < pp.size())
            {
                std::cout << "n must be smaller than the index type max value. " LOCATION << std::endl; // 输出错误信息
                throw RTE_LOC;                                                                          // 抛出异常
            }

            mPaxos.init(numItems, pp, paxosHashSeed);

            /*
            初始化BatchPIR
            */
            string selection = std::to_string(pirBatchSize) + "," + std::to_string(mPaxos.mSparseSize) + "," + std::to_string(pirEntrySize);
            // 创建加密参数，并初始化 BatchPirParams
            auto encryption_params = utils::create_encryption_parameters(selection);
            BatchPirParams batchPirParams(pirBatchSize, mPaxos.mSparseSize, pirEntrySize, encryption_params);
            batchPirParams.print_params();

            mServer = std::move(BatchPIRServer(batchPirParams));
        };

        void setKeysAndValues()
        {
            PRNG prng(ZeroBlock); // 初始化随机数生成器
            prng.get<block>(mKeys);
            prng.get<block>(mValues);
        };

        void setClientKeys(u32 client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> public_Key)
        {
            mServer.set_client_keys(client_id, public_Key);
        }
        std::unordered_map<std::string, u64> getServerHash()
        {
            return mServer.get_hash_map();
        };

        BatchPirParams getServerPirParams()
        {
            return mServer.getBatchPirParams();
        };

        vector<PIRResponseList> genResponses(u32 client_id, vector<vector<PIRQuery>> queries)
        {
            vector<PIRResponseList> responses;
            responses.reserve(queries.size());

            for (auto query : queries)
            {
                responses.emplace_back(mServer.generate_response(client_id, query));
            }
            return responses;
        };

        void paxosEncoding()
        {
            // 初始化随机数生成器
            srandom(time(NULL));
            block seed(random(), random());
            PRNG prng(seed);

            mPaxos.template solve<block>(mKeys, oc::span<block>(mValues), oc::span<block>(mEncoding), &prng); // 执行求解

            mServer.setEntries((uint8_t *)mEncoding.data());
        };

        void printParams()
        {
            std::cout << "+---------------------------------------------------+" << std::endl
                      << "|                    mPaxos Params                  |" << std::endl
                      << "+---------------------------------------------------+" << std::endl
                      << "| itemNum: " << mPaxos.mNumItems << std::endl
                      << "| mSparseSize: " << mPaxos.mSparseSize << std::endl
                      << "| mDenseSize: " << mPaxos.mDenseSize << std::endl
                      << "| DenseType: " << mPaxos.mDt << std::endl
                      << "| weight: " << mPaxos.mWeight << std::endl
                      << "+---------------------------------------------------+" << std::endl;
        };
    };

    template <typename IdxType>
    class OkvrRecv
    {
    public:
        Paxos<IdxType> mPaxos;
        BatchPIRClient mClient;

        std::vector<block> mKeys;
        std::vector<block> mValues;
        std::vector<block> mEncoding;

        OkvrRecv() {};

        void init(u64 clientNumItems, u64 serverNumItems, block paxosHashSeed, BatchPirParams batchPirParams, u64 paxosWeight = 3, u64 paxosSsp = 40, PaxosParam::DenseType paxosDT = PaxosParam::GF128)
        {
            // 默认 w=3,denseType为GF128,统计参数为40
            PaxosParam pp(serverNumItems, paxosWeight, paxosSsp, paxosDT);

            mKeys.resize(clientNumItems);
            mValues.resize(clientNumItems);
            mEncoding.resize(pp.size());

            // 检查n是否小于索引类型的最大值
            u64 maxN = std::numeric_limits<IdxType>::max() - 1;
            if (maxN < pp.size())
            {
                std::cout << "n must be smaller than the index type max value. " LOCATION << std::endl; // 输出错误信息
                throw RTE_LOC;                                                                          // 抛出异常
            }

            mPaxos.init(serverNumItems, pp, paxosHashSeed);

            // 初始化BatchPIR
            mClient = std::move(BatchPIRClient(batchPirParams));
        };

        void setKeysAndValues()
        {
            PRNG prng(ZeroBlock); // 初始化随机数生成器
            prng.get<block>(mKeys);
        };

        void setKeys()
        {
            PRNG prng(ZeroBlock); // 初始化随机数生成器
            prng.get<block>(mKeys);
        };

        void setServerHashMap(std::unordered_map<std::string, u64> map)
        {
            mClient.set_map(map);
        };

        std::pair<seal::GaloisKeys, seal::RelinKeys> getPublicKeys()
        {
            return mClient.get_public_keys();
        }

        /*
        仅支持计算 weight=3 的情况
        todo: 考虑并行化
        */
        vector<uint64_t> computeIndeies()
        {
            auto sparseSize = mPaxos.mSparseSize;
            vector<u8> results(sparseSize, 0);

            oc::Matrix<IdxType> rows(32, mPaxos.mWeight);
            vector<block> dense(32);
            IdxType *row = rows.data();

            auto inIter = mKeys.data();
            IdxType main = mKeys.size() / 32 * 32;

            for (u64 i = 0; i < main; i += 32)
            {
                mPaxos.mHasher.hashBuildRow32(inIter + i, row, dense.data());
                for (u64 j = 0; j < 32 * mPaxos.mWeight; j++)
                {
                    results[*(row + j)] = 1;
                }
            }

            for (u64 i = main; i < mKeys.size(); i++)
            {
                mPaxos.mHasher.hashBuildRow1(inIter + i, rows.data(), dense.data());
                for (u64 j = 0; j < mPaxos.mWeight; j++)
                {
                    results[*(row + j)] = 1;
                }
            }

            vector<uint64_t> result2;

            for (u64 i = 0; i < sparseSize; i++)
            {
                if (results[i] == 1)
                {
                    result2.push_back(i);
                }
            }

            std::cout << "computeIndeies::size: " << result2.size() << std::endl;
            return result2;
        }

        vector<vector<PIRQuery>> genQueies(vector<uint64_t> indeies)
        {
            u64 batchSize = mClient.getBatchPirParams().get_batch_size();
            u64 vectorNum = (indeies.size() + batchSize - 1) / batchSize;
            u64 remainderSize = indeies.size() % batchSize;
            std::cout << "genQueies::vectorNum: " << vectorNum << ", remainderSize: " << remainderSize << std::endl;
            if (remainderSize != 0)
            {
                u64 paddingSize = batchSize - remainderSize;
                std::cout << "genQueies::paddingSize: " << paddingSize << std::endl;
                indeies.resize(indeies.size() + paddingSize, 0);
                std::cout << "genQueies::indeies.size(): " << indeies.size() << std::endl;
            }

            vector<vector<u64>> chunks;
            chunks.reserve(vectorNum);

            for (u64 i = 0; i < indeies.size(); i += batchSize)
            {
                auto end = std::min(i + batchSize, indeies.size());
                chunks.emplace_back(indeies.begin() + i, indeies.begin() + end);
            }

            vector<vector<PIRQuery>> results;
            results.reserve(vectorNum);

            for (auto chunk : chunks)
            {
                results.emplace_back(mClient.create_queries(chunk));
            }

            std::cout << "genQueies::size: " << results.size() << std::endl;

            return results;
        };

        vector<vector<RawDB>> answerResponses(vector<PIRResponseList> responseLists)
        {
            vector<vector<RawDB>> results;
            results.reserve(responseLists.size());
            for (auto responseList : responseLists)
            {
                results.emplace_back(mClient.decode_responses_chunks(responseList));
            }
            return results;
        };

        void handleEncodingSparse(vector<vector<RawDB>> answerDBs)
        {
            auto defaultValue = mClient.getBatchPirParams().get_default_value();

            for (u64 i = 0; i < answerDBs.size(); i++)
            {
                auto rawDB = answerDBs[i][0];
                auto cuckooTables = mClient.getCuckooTables();
                auto cuckooTable = cuckooTables[i];

                for (int j = 0; j < cuckooTable.size(); j++)
                {
                    if (cuckooTable[j] != defaultValue)
                    {
                        auto tmp = rawDB[j];

                        memcpy((u8 *)(&(mEncoding[cuckooTable[j]])), tmp.data(), 16);
                    }
                }
            }
        }

        void paxosDecoding()
        {
            mPaxos.template decode<block>(mKeys, oc::span<block>(mValues), oc::span<block>(mEncoding)); // 执行解码
        };
    };
}