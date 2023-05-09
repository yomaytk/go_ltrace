#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 256

// Struct for holding person data
typedef struct {
    char name[MAX_LINE_LENGTH];
    int age;
    double height;
} Person;

// Function prototypes
void create_random_numbers_file(const char *filename, int count);
double calculate_mean(const char *filename);
double calculate_standard_deviation(const char *filename, double mean);
void print_current_time(void);
void uppercase_string(char *str);
int compare_persons(const void *a, const void *b);
void sort_persons(const char *filename);
int read_persons(const char *filename, Person *persons, int max_count);
void write_persons(const char *filename, Person *persons, int count);
void create_persons_file(const char *filename, int count);

int main(void) {
    const char *filename = "random_numbers.txt";
    int count = 100;

    srand(time(NULL)); // Seed the random number generator

    // Create a file with random numbers
    create_random_numbers_file(filename, count);

    // Calculate the mean of the numbers in the file
    double mean = calculate_mean(filename);
    printf("Mean: %f\n", mean);

    // Calculate the standard deviation of the numbers in the file
    double std_dev = calculate_standard_deviation(filename, mean);
    printf("Standard Deviation: %f\n", std_dev);

    // Print the current date and time
    print_current_time();

    // Convert a string to uppercase
    char sample_str[] = "Hello, World!";
    uppercase_string(sample_str);
    printf("Uppercase string: %s\n", sample_str);

    // Create a persons file with random data
    const char *persons_file = "persons.txt";
    create_persons_file(persons_file, 100);

    // Sort persons by age in a file
    sort_persons(persons_file);

    return 0;
}


void create_random_numbers_file(const char *filename, int count) {
    printf("create_random_numbers_file start.\n");
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < count; i++) {
        int random_number = rand() % 100;
        fprintf(file, "%d\n", random_number);
    }

    fclose(file);
    printf("create_random_numbers_file end.\n");
}

double calculate_mean(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    double sum = 0;
    int count = 0;
    int number;

    while (fscanf(file, "%d", &number) != EOF) {
        sum += number;
        count++;
    }

    fclose(file);

    return sum / count;
}

double calculate_standard_deviation(const char *filename, double mean) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    double sum = 0;
    int count = 0;
        int number;

    while (fscanf(file, "%d", &number) != EOF) {
        double diff = number - mean;
        sum += diff * diff;
        count++;
    }

    fclose(file);

    return sqrt(sum / count);
}

void print_current_time(void) {
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    printf("Current local time and date: %s", asctime(timeinfo));
}

void uppercase_string(char *str) {
    while (*str) {
        *str = toupper(*str);
        str++;
    }
}

int compare_persons(const void *a, const void *b) {
    const Person *pa = (const Person *)a;
    const Person *pb = (const Person *)b;

    return pa->age - pb->age;
}

void sort_persons(const char *filename) {
    Person persons[100];
    int count;

    count = read_persons(filename, persons, 100);
    qsort(persons, count, sizeof(Person), compare_persons);
    write_persons(filename, persons, count);
}

int read_persons(const char *filename, Person *persons, int max_count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    int i = 0;
    while (i < max_count && fscanf(file, "%s %d %lf", persons[i].name, &persons[i].age, &persons[i].height) == 3) {
        i++;
    }

    fclose(file);
    return i;
}

void create_persons_file(const char *filename, int count) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    const char *names[] = {"Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Helen", "Igor", "Jack"};

    for (int i = 0; i < count; i++) {
        const char *name = names[rand() % (sizeof(names) / sizeof(names[0]))];
        int age = rand() % 100;
        double height = 4.0 + ((double)rand() / RAND_MAX) * 3.0;
        fprintf(file, "%s %d %.2lf\n", name, age, height);
    }

    fclose(file);
}


void write_persons(const char *filename, Person *persons, int count) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < count; i++) {
        fprintf(file, "%s %d %.2lf\n", persons[i].name, persons[i].age, persons[i].height);
    }

    fclose(file);
}

