#include "perf.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Common/Timer.h"

#include "volePSI/Defines.h"
#include "volePSI/config.h"
#include "volePSI/SimpleIndex.h"
#include "volePSI/PxUtil.h"
#include "volePSI/Paxos.h"

#include "ourImp/Okvr.h"

#include "libdivide.h"
using namespace oc;
using namespace volePSI;
using namespace deadline;

void perf(oc::CLP &cmd)
{
	if (cmd.isSet("okvr"))
		perfOkvr(cmd);
	if (cmd.isSet("paxos"))
		perfPaxos(cmd);
	if (cmd.isSet("baxos"))
		perfBaxos(cmd);
}

void perfOkvr(oc::CLP &cmd)
{
	auto bits = cmd.getOr("b", 16);
	switch (bits)
	{
	case 8:
		perfOkvrImpl<u8>(cmd);
		break;
	case 16:
		perfOkvrImpl<u16>(cmd);
		break;
	case 32:
		perfOkvrImpl<u32>(cmd);
		break;
	case 64:
		perfOkvrImpl<u64>(cmd);
		break;
	default:
		std::cout << "b must be 8, 16, 32 or 64. " LOCATION << std::endl;
		throw RTE_LOC;
	}
}

template <typename IdxType>
void perfOkvrImpl(oc::CLP &cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10)); // 获取要处理的元素数量, 2^n
	auto batchSize = cmd.getOr("batch", 128);
	OkvrSender<IdxType>
		okvrS;
	okvrS.init(n, block(1, 1), batchSize);
	okvrS.printParams();
	okvrS.setKeysAndValues();
	okvrS.paxosEncoding();

	OkvrRecv<IdxType> okvrR;
	okvrR.init(n, n, block(1, 1), okvrS.getServerPirParams());
	okvrR.setKeys();

	std::cout << "获取 server map 开始!" << std::endl;
	auto serverHash = okvrS.getServerHash();
	okvrR.setServerHashMap(serverHash);
	std::cout << "获取 server map 完成!" << std::endl;

	std::cout << "获取 client PK 开始!" << std::endl;
	auto pks = okvrR.getPublicKeys();
	okvrS.setClientKeys(0, pks);
	std::cout << "获取 client PK 完成!" << std::endl;

	std::cout << "计算 查询索引 开始!" << std::endl;
	vector<u64> indexes = okvrR.computeIndeies();
	std::cout << "计算 查询索引 完成!" << std::endl;

	std::cout << "生成 Query 开始!" << std::endl;
	vector<vector<PIRQuery>> queies = okvrR.genQueies(indexes);
	std::cout << "生成 Query 完成!" << std::endl;

	std::cout << "生成 Response 开始!" << std::endl;
	vector<PIRResponseList> responses = okvrS.genResponses(0, queies);
	std::cout << "生成 Response 完成!" << std::endl;

	std::cout << "Answer 开始!" << std::endl;
	vector<vector<RawDB>> answers = okvrR.answerResponses(responses);
	std::cout << "Answer 完成!" << std::endl;

	okvrR.handleEncodingSparse(answers);

	for (auto index : indexes)
	{
		auto a = okvrS.mEncoding[index];
		auto b = okvrR.mEncoding[index];
		if (a != b)
		{
			std::cout << "error: index- " << index << ", " << a << ", " << b << std::endl;
		}
	}

	// okvrR.paxosDecoding();

	indexes.clear();
	queies.clear();
	responses.clear();
	answers.clear();
}

void perfPaxos(oc::CLP &cmd)
{
	auto bits = cmd.getOr("b", 16);
	switch (bits)
	{
	case 8:
		perfPaxosImpl<u8>(cmd);
		break;
	case 16:
		perfPaxosImpl<u16>(cmd);
		break;
	case 32:
		perfPaxosImpl<u32>(cmd);
		break;
	case 64:
		perfPaxosImpl<u64>(cmd);
		break;
	default:
		std::cout << "b must be 8,16,32 or 64. " LOCATION << std::endl;
		throw RTE_LOC;
	}
}

/**
 * @brief 执行Paxos算法的性能测试实现。
 *
 * @tparam T 数据类型模板参数。
 * @param cmd 命令行参数，包含算法配置选项。
 *
 * 该函数根据提供的命令行参数初始化Paxos算法，并执行指定次数的算法运行。
 * 在每次运行中，算法会根据输入的密钥和数据进行编码和解码，并记录时间。
 * 最后，输出总的执行时间。
 *
 * @note 该函数会抛出异常，如果n的值超过了类型T的最大值。
 */
template <typename T>
void perfPaxosImpl(oc::CLP &cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10)); // 获取要处理的元素数量, 2^n
	u64 maxN = std::numeric_limits<T>::max() - 1;		  // 获取类型T的最大值
	auto t = cmd.getOr("t", 1ull);						  // 获取 the number of trials
	// auto rand = cmd.isSet("rand");
	auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);						// 获取详细输出标志
	auto w = cmd.getOr("w", 3);												// 获取 The okvs weight
	auto ssp = cmd.getOr("ssp", 40);										// 获取 statistical security parameter
	auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128; // 获取dense type类型 Binary or GF128
	auto cols = cmd.getOr("cols", 0);										// 获取列数

	PaxosParam pp(n, w, ssp, dt); // 初始化Paxos参数
	// std::cout << "e=" << pp.size() / double(n) << std::endl; // 输出每个元素的大小
	if (maxN < pp.size()) // 检查n是否小于索引类型的最大值
	{
		std::cout << "n must be smaller than the index type max value. " LOCATION << std::endl; // 输出错误信息
		throw RTE_LOC;																			// 抛出异常
	}

	auto m = cols ? cols : 1;  // 如果 cols ，则使用，否则默认为1
	std::vector<block> key(n); // 创建密钥向量
	oc::Matrix<block> val(n, m), pax(pp.size(), m);
	PRNG prng(ZeroBlock); // 初始化随机数生成器
	prng.get<block>(key);
	prng.get<block>(val);

	Timer timer;							  // 初始化计时器
	auto start = timer.setTimePoint("start"); // 设置开始时间点
	auto end = start;						  // 结束时间点初始化
	for (u64 i = 0; i < t; ++i)				  // 执行t次
	{
		Paxos<T> paxos;					// 创建Paxos对象
		paxos.init(n, pp, block(i, i)); // 初始化Paxos

		if (v > 1)				   // 如果需要详细输出
			paxos.setTimer(timer); // 设置计时器

		if (cols) // 如果设置了列数
		{
			paxos.setInput(key);						 // 设置输入密钥
			paxos.template encode<block>(val, pax);		 // 执行编码
			timer.setTimePoint("s" + std::to_string(i)); // 设置时间点
			paxos.template decode<block>(key, val, pax); // 执行解码
		}
		else // 如果没有设置列数
		{
			paxos.template solve<block>(key, oc::span<block>(val), oc::span<block>(pax));  // 执行求解
			timer.setTimePoint("s" + std::to_string(i));								   // 设置时间点
			paxos.template decode<block>(key, oc::span<block>(val), oc::span<block>(pax)); // 执行解码
		}

		end = timer.setTimePoint("d" + std::to_string(i)); // 设置结束时间点
	}

	if (v)								 // 如果需要详细输出
		std::cout << timer << std::endl; // 输出计时器信息

	auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000); // 计算总时间
	std::cout << "total " << tt << "ms" << std::endl;													 // 输出总时间
}

void perfBaxos(oc::CLP &cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	auto t = cmd.getOr("t", 1ull);
	// auto rand = cmd.isSet("rand");
	auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);
	auto w = cmd.getOr("w", 3);
	auto ssp = cmd.getOr("ssp", 40);
	auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;
	auto nt = cmd.getOr("nt", 0);

	// PaxosParam pp(n, w, ssp, dt);
	auto binSize = 1 << cmd.getOr("lbs", 15);
	u64 baxosSize;
	{
		Baxos paxos;
		paxos.init(n, binSize, w, ssp, dt, oc::ZeroBlock);
		baxosSize = paxos.size();
	}
	std::vector<block> key(n), val(n), pax(baxosSize);
	PRNG prng(ZeroBlock);
	prng.get<block>(key);
	prng.get<block>(val);

	Timer timer;
	auto start = timer.setTimePoint("start");
	auto end = start;
	for (u64 i = 0; i < t; ++i)
	{
		Baxos paxos;
		paxos.init(n, binSize, w, ssp, dt, block(i, i));

		// if (v > 1)
		//	paxos.setTimer(timer);

		paxos.solve<block>(key, val, pax, nullptr, nt);
		timer.setTimePoint("s" + std::to_string(i));

		paxos.decode<block>(key, val, pax, nt);

		end = timer.setTimePoint("d" + std::to_string(i));
	}

	if (v)
		std::cout << timer << std::endl;

	auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
	std::cout << "total " << tt << "ms, e=" << double(baxosSize) / n << std::endl;
}

void overflow(CLP &cmd)
{
	auto statSecParam = 40;
	std::vector<std::vector<u64>> sizes;
	for (u64 numBins = 1; numBins <= (1ull << 32); numBins *= 2)
	{
		sizes.emplace_back();
		try
		{
			for (u64 numBalls = 1; numBalls <= (1ull << 32); numBalls *= 2)
			{
				auto s0 = SimpleIndex::get_bin_size(numBins, numBalls, statSecParam, true);
				sizes.back().push_back(s0);
				std::cout << numBins << " " << numBalls << " " << s0 << std::endl;
			}
		}
		catch (...)
		{
		}
	}

	for (u64 i = 0; i < sizes.size(); ++i)
	{
		std::cout << "/*" << i << "*/ {{ ";
		for (u64 j = 0; j < sizes[i].size(); ++j)
		{
			if (j)
				std::cout << ", ";
			std::cout << std::log2(sizes[i][j]);
		}
		std::cout << " }}," << std::endl;
	}
}
