import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { Field, ArgsType } from '@nestjs/graphql';

@ArgsType()
export class ResetPasswordUserInput {
  @Field()
  @IsNotEmpty()
  @IsString()
  newPassword: string;

  @Field()
  @IsNotEmpty()
  @IsString()
  oldPassword: string;

}
