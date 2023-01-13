import { IsInt, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { Field, ArgsType } from '@nestjs/graphql';
import { Transform } from 'class-transformer';

@ArgsType()
export class CreateUserInput {
  @Field()
  @IsNotEmpty()
  @IsString()
  countryCode: string;

  @Field()
  @IsNotEmpty()
  @IsString()
  mobile: string;

  @Field()
  @IsNotEmpty()
  @IsString()
  password: any;

  @Field()
  @IsOptional()
  @IsString()
  email: string;

  @Field()
  @IsOptional()
  @IsString()
  name: string;

  @Field()
  @IsOptional()
  @IsString()
  insuranceCompanyName: string;

  @Field()
  @IsOptional()
  @IsString()
  companyWork: string;
}
