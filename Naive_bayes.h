#ifndef NAIVEBAYES_H
#define NAIVEBAYES_H

typedef struct class_summary
{
    std::vector<std::vector<float>> Mean_Stdev;
    float class_prob;

} class_summary;

class Naive_Bayes
{
    private:
    std::vector<class_summary> Summary;
    std::vector<float> unique_label;

    public:
    void fit(std::vector<std::vector<float>> dataset);
    int predict(const  std::vector<float>& test_data);
};

class_summary calculate_Class_Summary(std::vector<std::vector<float>> dataset, float class_label);
float prob_By_Summary(const std::vector<float> &test_data ,const class_summary &summary );
#endif
